# Copyright 2013 Openstack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
NVP client driver for Quark
"""

from oslo.config import cfg

import aiclib
from quantum.openstack.common import log as logging

from quark.drivers import base
from quark import exceptions


LOG = logging.getLogger("quantum.quark.nvplib")

CONF = cfg.CONF

nvp_opts = [
    cfg.IntOpt('max_ports_per_switch',
               default=0,
               help=_('Maximum amount of NVP ports on an NVP lswitch')),
    cfg.StrOpt('default_tz',
               help=_('The default transport zone UUID')),
    cfg.MultiStrOpt('controller_connection',
                    default=[],
                    help=_('NVP Controller connection string')),
]

physical_net_type_map = {
    "stt": "stt",
    "gre": "gre",
    "flat": "bridge",
    "bridge": "bridge",
    "vlan": "bridge",
    "local": "local"
}

CONF.register_opts(nvp_opts, "NVP")


class NVPDriver(base.BaseDriver):
    def __init__(self):
        self.nvp_connections = []
        self.conn_index = 0
        self.max_ports_per_switch = 0

    def load_config(self, path):
        #NOTE(mdietz): What does default_tz actually mean?
        #              We don't have one default.
        default_tz = CONF.NVP.default_tz
        LOG.info("Loading NVP settings " + str(default_tz))
        connections = CONF.NVP.controller_connection
        self.max_ports_per_switch = CONF.NVP.max_ports_per_switch
        LOG.info("Loading NVP settings " + str(connections))
        for conn in connections:
            (ip, port, user, pw, req_timeout,
             http_timeout, retries, redirects) = conn.split(":")

            self.nvp_connections.append(dict(ip_address=ip,
                                        port=port,
                                        username=user,
                                        password=pw,
                                        req_timeout=req_timeout,
                                        http_timeout=http_timeout,
                                        retries=retries,
                                        redirects=redirects,
                                        default_tz=default_tz))

    def get_connection(self):
        conn = self.nvp_connections[self.conn_index]
        if "connection" not in conn:
            scheme = conn["port"] == "443" and "https" or "http"
            uri = "%s://%s:%s" % (scheme, conn["ip_address"], conn["port"])
            user = conn['username']
            passwd = conn['password']
            conn["connection"] = aiclib.nvp.Connection(uri,
                                                       username=user,
                                                       password=passwd)
        return conn["connection"]

    def create_network(self, context, network_name, tags=None,
                       network_id=None, **kwargs):
        return self._lswitch_create(context, network_name, tags,
                                    network_id, **kwargs)

    def delete_network(self, context, network_id):
        lswitches = self._lswitches_for_network(context, network_id).results()
        connection = self.get_connection()
        for switch in lswitches["results"]:
            LOG.debug("Deleting lswitch %s" % switch["uuid"])
            connection.lswitch(switch["uuid"]).delete()

    def create_port(self, context, network_id, port_id, status=True):
        tenant_id = context.tenant_id
        lswitch = self._create_or_choose_lswitch(context, network_id)
        connection = self.get_connection()
        port = connection.lswitch_port(lswitch)
        port.admin_status_enabled(status)
        tags = [dict(tag=network_id, scope="quantum_net_id"),
                dict(tag=port_id, scope="quantum_port_id"),
                dict(tag=tenant_id, scope="os_tid")]
        LOG.debug("Creating port on switch %s" % lswitch)
        port.tags(tags)
        res = port.create()
        res["lswitch"] = lswitch
        return res

    def delete_port(self, context, port_id, lswitch_uuid=None):
        connection = self.get_connection()
        if not lswitch_uuid:
            query = connection.lswitch_port("*").query()
            query.relations("LogicalSwitchConfig")
            query.uuid(port_id)
            port = query.results()
            if port["result_count"] > 1:
                raise Exception("More than one lswitch for port %s" % port_id)
            for r in port["results"]:
                lswitch_uuid = r["_relations"]["LogicalSwitchConfig"]["uuid"]
        LOG.debug("Deleting port %s from lswitch %s" % (port_id, lswitch_uuid))
        connection.lswitch_port(lswitch_uuid, port_id).delete()

    def _get_network_details(self, context, network_id, switches):
        name, phys_net, phys_type, segment_id = None, None, None, None
        for res in switches["results"]:
            name = res["display_name"]
            for zone in res["transport_zones"]:
                phys_net = zone["zone_uuid"]
                phys_type = zone["transport_type"]
                if "binding_config" in zone:
                    binding = zone["binding_config"]
                    segment_id = binding["vlan_translation"][0]["transport"]
                break
            return dict(network_name=name, phys_net=phys_net,
                        phys_type=phys_type, segment_id=segment_id)
        return {}

    def _create_or_choose_lswitch(self, context, network_id):
        switches = self._lswitch_status_query(context, network_id)
        switch = self._lswitch_select_open(context, network_id=network_id,
                                           switches=switches)
        if switch:
            LOG.debug("Found open switch %s" % switch)
            return switch

        switch_details = self._get_network_details(context, network_id,
                                                   switches)
        if not switch_details:
            raise exceptions.BadNVPState(net_id=network_id)

        return self._lswitch_create(context, network_id=network_id,
                                    **switch_details)

    def _lswitch_status_query(self, context, network_id):
        query = self._lswitches_for_network(context, network_id)
        query.relations("LogicalSwitchStatus")
        results = query.results()
        LOG.debug("Query results: %s" % results)
        return results

    def _lswitch_select_open(self, context, switches=None, **kwargs):
        """Selects an open lswitch for a network. Note that it does not select
        the most full switch, but merely one with ports available.
        """
        if switches is not None:
            for res in switches["results"]:
                count = res["_relations"]["LogicalSwitchStatus"]["lport_count"]
                if self.max_ports_per_switch == 0 or \
                        count < self.max_ports_per_switch:
                    return res["uuid"]
        return None

    def _lswitch_delete(self, context, lswitch_uuid):
        connection = self.get_connection()
        LOG.debug("Deleting lswitch %s" % lswitch_uuid)
        connection.lswitch(lswitch_uuid).delete()

    def _config_provider_attrs(self, connection, switch, phys_net,
                               net_type, segment_id):
        if not (phys_net or net_type):
            return
        if not phys_net and net_type:
            raise exceptions.ProvidernetParamError(
                msg="provider:physical_network parameter required")
        if phys_net and not net_type:
            raise exceptions.ProvidernetParamError(
                msg="provider:network_type parameter required")
        if not net_type in ("bridge", "vlan") and segment_id:
            raise exceptions.SegmentIdUnsupported(net_type=net_type)
        if net_type == "vlan" and not segment_id:
            raise exceptions.SegmentIdRequired(net_type=net_type)

        phys_type = physical_net_type_map.get(net_type.lower())
        if not phys_type:
            raise exceptions.InvalidPhysicalNetworkType(net_type=net_type)

        tz_query = connection.transportzone(phys_net).query()
        transport_zone = tz_query.results()

        if transport_zone["result_count"] == 0:
            raise exceptions.PhysicalNetworkNotFound(phys_net=phys_net)
        switch.transport_zone(zone_uuid=phys_net,
                              transport_type=phys_type,
                              vlan_id=segment_id)

    def _lswitch_create(self, context, network_name=None, tags=None,
                        network_id=None, phys_net=None,
                        phys_type=None, segment_id=None,
                        **kwargs):
        # NOTE(mdietz): physical net uuid maps to the transport zone uuid
        # physical net type maps to the transport/connector type
        # if type maps to 'bridge', then segment_id, which maps
        # to vlan_id, is conditionally provided
        LOG.debug("Creating new lswitch for %s network %s" %
                 (context.tenant_id, network_name))

        tenant_id = context.tenant_id
        connection = self.get_connection()

        switch = connection.lswitch()
        if network_name is None:
            network_name = network_id
        switch.display_name(network_name)
        tags = tags or []
        tags.append({"tag": tenant_id, "scope": "os_tid"})
        if network_id:
            tags.append({"tag": network_id, "scope": "quantum_net_id"})
        switch.tags(tags)
        LOG.debug("Creating lswitch for network %s" % network_id)

        # When connecting to public or snet, we need switches that are
        # connected to their respective public/private transport zones
        # using a "bridge" connector. Public uses no VLAN, whereas private
        # uses VLAN 122 in netdev. Probably need this to be configurable
        self._config_provider_attrs(connection, switch, phys_net, phys_type,
                                    segment_id)
        res = switch.create()
        return res["uuid"]

    def _lswitches_for_network(self, context, network_id):
        connection = self.get_connection()
        query = connection.lswitch().query()
        query.tagscopes(['os_tid', 'quantum_net_id'])
        query.tags([context.tenant_id, network_id])
        return query
