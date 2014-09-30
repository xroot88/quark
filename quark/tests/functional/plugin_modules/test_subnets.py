# Copyright 2013 Openstack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for# the specific language governing permissions and limitations
#  under the License.

import mock
import netaddr
from oslo.config import cfg

import contextlib

from quark.db import api as db_api
import quark.ipam
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkGetSubnets(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub1 = db_api.subnet_create(self.context, **subnet)
            subnet["id"] = 2
            sub2 = db_api.subnet_create(self.context, do_not_use=True,
                                        **subnet)
        yield net_mod, sub1, sub2

    def test_get_subnet_do_not_use_not_returned(self):
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      ip_policy=None, tenant_id="fake")
        with self._stubs(network, subnet) as (net, sub1, sub2):
            subnets = db_api.subnet_find_allocation_counts(self.context,
                                                           net["id"]).all()
            self.assertEqual(len(subnets), 1)
            self.assertEqual(subnets[0][0]["id"], "1")


class QuarkGetSubnetsFromPlugin(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(mock.patch("neutron.common.rpc.get_notifier")):
            net = network_api.create_network(self.context, network)
            subnet['subnet']['network_id'] = net['id']
            sub1 = subnet_api.create_subnet(self.context, subnet)
            yield net, sub1

    def test_toggle_ip_policy_id_from_subnet_view(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake")
        subnet = {"subnet": subnet}
        original = cfg.CONF.QUARK.show_subnet_ip_policy_id
        with self._stubs(network, subnet) as (net, sub1):
            cfg.CONF.set_override('show_subnet_ip_policy_id', True, "QUARK")
            subnet = subnet_api.get_subnet(self.context, 1)
            self.assertTrue('ip_policy_id' in subnet)
            cfg.CONF.set_override('show_subnet_ip_policy_id', False, "QUARK")
            subnet = subnet_api.get_subnet(self.context, 1)
            self.assertFalse('ip_policy_id' in subnet)
        cfg.CONF.set_override('show_subnet_ip_policy_id', original, "QUARK")


class QuarkCreateSubnets(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(mock.patch("neutron.common.rpc.get_notifier")):
            net = network_api.create_network(self.context, network)
            subnet['subnet']['network_id'] = net['id']
            sub1 = subnet_api.create_subnet(self.context, subnet)
            yield net, sub1

    def test_create_allocation_pools_empty(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = []
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            self.assertEqual(sub1["allocation_pools"], [])

    def test_create_allocation_pools_none(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = None
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            self.assertEqual(sub1["allocation_pools"],
                             [dict(start="192.168.1.1", end="192.168.1.254")])

    def test_create_allocation_pools_full(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        pools = [dict(start="192.168.1.0", end="192.168.1.255")]
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake", allocation_pools=pools)
        subnet = {"subnet": subnet}
        with self._stubs(network, subnet) as (net, sub1):
            self.assertEqual(sub1["allocation_pools"],
                             [dict(start="192.168.1.1", end="192.168.1.254")])
