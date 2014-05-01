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

import netaddr

import sqlalchemy as sa
from sqlalchemy import func
from sqlalchemy import orm

from sqlalchemy.ext import associationproxy
from sqlalchemy.ext import declarative
from sqlalchemy.ext import hybrid

import neutron.db.model_base
from neutron.db import models_v2 as models
from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils

from quark.db import custom_types
#NOTE(mdietz): This is the only way to actually create the quotas table,
#              regardless if we need it. This is how it's done upstream.
#NOTE(jhammond): If it isn't obvious quota_driver is unused and that's ok.
#                 DO NOT DELETE IT!!!
from quark import quota_driver  # noqa

HasId = models.HasId

LOG = logging.getLogger(__name__)
TABLE_KWARGS = {"mysql_engine": "InnoDB"}


def _default_list_getset(collection_class, proxy):
    attr = proxy.value_attr

    def getter(obj):
        if obj:
            return getattr(obj, attr, None)
        return []

    if collection_class is dict:
        setter = lambda o, k, v: setattr(o, attr, v)
    else:
        setter = lambda o, v: setattr(o, attr, v)
    return getter, setter


class QuarkBase(neutron.db.model_base.NeutronBaseV2):
    created_at = sa.Column(sa.DateTime(), default=timeutils.utcnow)
    __table_args__ = TABLE_KWARGS


BASEV2 = declarative.declarative_base(cls=QuarkBase)


class CIDRMixin(object):
    CIDR_WIDTH = 128

    @hybrid.hybrid_property
    def cidr(self):
        return netaddr.IPNetwork((self.address.value, self.prefix))

    @cidr.setter
    def cidr(self, value):
        if not isinstance(value, netaddr.IPNetwork):
            value = netaddr.IPNetwork(value)

        value = value.ipv6()

        self.address = value[0]
        self.prefix = value.prefixlen

    @hybrid.hybrid_property
    def last(self):
        return self.cidr.last

    # NOTE(jkoelker) SQL version of ADDR | (( 1 << (WIDTH - PREFIX)) -1 )
    #                Determines the largest integer within the prefix.
    @last.expression
    def last(cls):
        mask = func.pow(2, (cls.CIDR_WIDTH - cls.prefix)) - 1
        return cls.address.op('|')(mask)

    def cidr_map(self):
        return self.cidr

    @classmethod
    def _split_cidr(cls, cidr):
        cidr = netaddr.IPNetwork(cidr)
        return cidr[0], cidr.prefixlen

    def __init__(self, *args, **kwargs):
        cidr = kwargs.pop('cidr', None)

        if cidr is not None:
            address, prefix = self._split_cidr(cidr)
            kwargs['address'] = address
            kwargs['prefix'] = prefix

        super(CIDRMixin, self).__init__(*args, **kwargs)

    def __str__(self):
        return str(self.cidr_map())

        if self.cidr_is_mapped(self.cidr):
            return str(self.cidr.ipv4())

        return str(self.cidr)


class TagAssociation(BASEV2, models.HasId):
    __tablename__ = "quark_tag_associations"

    discriminator = sa.Column(sa.String(255))
    tags = associationproxy.association_proxy("tags_association", "tag",
                                              creator=lambda t: Tag(tag=t))

    @classmethod
    def creator(cls, discriminator):
        return lambda tags: TagAssociation(tags=tags,
                                           discriminator=discriminator)

    @property
    def parent(self):
        """Return the parent object."""
        return getattr(self, "%s_parent" % self.discriminator)


class Tag(BASEV2, models.HasId, models.HasTenant):
    __tablename__ = "quark_tags"
    association_uuid = sa.Column(sa.String(36),
                                 sa.ForeignKey(TagAssociation.id),
                                 nullable=False)

    tag = sa.Column(sa.String(255), nullable=False)
    parent = associationproxy.association_proxy("association", "parent")
    association = orm.relationship("TagAssociation",
                                   backref=orm.backref("tags_association"))


class IsHazTags(object):
    @declarative.declared_attr
    def tag_association_uuid(cls):
        return sa.Column(sa.String(36), sa.ForeignKey(TagAssociation.id),
                         nullable=True)

    @declarative.declared_attr
    def tag_association(cls):
        discriminator = cls.__name__.lower()
        creator = TagAssociation.creator(discriminator)
        kwargs = {'creator': creator,
                  'getset_factory': _default_list_getset}
        cls.tags = associationproxy.association_proxy("tag_association",
                                                      "tags", **kwargs)
        backref = orm.backref("%s_parent" % discriminator, uselist=False)
        return orm.relationship("TagAssociation", backref=backref)


class IPAddress(BASEV2, models.HasId):
    """More closely emulate the melange version of the IP table.

    We always mark the record as deallocated rather than deleting it.
    Gives us an IP address owner audit log for free, essentially.
    """
    __tablename__ = "quark_ip_addresses"
    __table_args__ = (sa.UniqueConstraint("subnet_id", "address"),
                      TABLE_KWARGS)

    address_readable = sa.Column(sa.String(128), nullable=False)
    address = sa.Column(custom_types.INET(), nullable=False, index=True)
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey("quark_subnets.id",
                                        ondelete="CASCADE"))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("quark_networks.id",
                                         ondelete="CASCADE"))
    version = sa.Column(sa.Integer(), index=True)
    allocated_at = sa.Column(sa.DateTime())
    subnet = orm.relationship("Subnet", lazy="joined")
    # Need a constant to facilitate the indexed search for new IPs
    _deallocated = sa.Column(sa.Boolean())
    # Legacy data
    used_by_tenant_id = sa.Column(sa.String(255))
    deallocated_at = sa.Column(sa.DateTime(), index=True)

    @hybrid.hybrid_property
    def deallocated(self):
        return self._deallocated and not self.ports

    @deallocated.setter
    def deallocated(self, val):
        self._deallocated = val
        self.deallocated_at = None
        if val:
            self.deallocated_at = timeutils.utcnow()
            self.allocated_at = None

    # TODO(jkoelker) update the expression to use the jointable as well
    @deallocated.expression
    def deallocated(cls):
        return IPAddress._deallocated

    def cidr_map(self):
        if self.cidr.is_ipv4_mapped():
            return self.cidr.ipv4()

        return self.cidr


class Route(BASEV2, models.HasTenant, models.HasId, IsHazTags):
    __tablename__ = "quark_routes"
    cidr = sa.Column(sa.String(64))
    gateway = sa.Column(sa.String(64))
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey("quark_subnets.id",
                                                       ondelete="CASCADE"))


class DNSNameserver(BASEV2, models.HasTenant, models.HasId, IsHazTags):
    __tablename__ = "quark_dns_nameservers"
    ip = sa.Column(custom_types.INET())
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey("quark_subnets.id",
                                                       ondelete="CASCADE"))


class Subnet(CIDRMixin, BASEV2, models.HasId, IsHazTags):
    """Upstream model for IPs.

    Subnet -> has_many(IPAllocationPool)
    IPAllocationPool -> has_many(IPAvailabilityRange)
        As well as first and last _ip markers for some unknown reason
        first_ip is min(ranges), last_ip is max(ranges)
    IPAvailabilityRange -> belongs_to(IPAllocationPool)
        Also has first and last _ip, but only for the range
    IPAllocation -> belongs_to(port, subnet, network) but NOT IPAllocationPool

    IPAllocationPool and Range seem superfluous. Just create intelligent CIDRs
    for your subnet
    """
    __tablename__ = "quark_subnets"
    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36), sa.ForeignKey('quark_networks.id'))
    address = sa.Column(custom_types.INET, nullable=False)
    prefix = sa.Column(sa.Integer, nullable=False)
    tenant_id = sa.Column(sa.String(255), index=True)
    segment_id = sa.Column(sa.String(255), index=True)
    first_ip = sa.Column(custom_types.INET())
    last_ip = sa.Column(custom_types.INET())
    ip_version = sa.Column(sa.Integer())
    next_auto_assign_ip = sa.Column(custom_types.INET())

    @hybrid.hybrid_property
    def cidr(self):
        return netaddr.IPNetwork((self.address.value, self.prefix))

    @cidr.setter
    def cidr(self, value):
        if not isinstance(value, netaddr.IPNetwork):
            value = netaddr.IPNetwork(value)

        value = value.ipv6()

        self.address = value[0]
        self.prefix = value.prefixlen
        self.first_ip = value[0]
        self.last_ip = value[-1]
        self.next_auto_assign_ip = self.first_ip

        if value.is_ipv4_mapped():
            self.ip_version = 4

        else:
            self.ip_version = 6

    allocated_ips = orm.relationship(IPAddress,
                                     primaryjoin='and_(Subnet.id=='
                                     'IPAddress.subnet_id,'
                                     'IPAddress._deallocated != 1)')
    generated_ips = orm.relationship(IPAddress,
                                     primaryjoin='Subnet.id=='
                                     'IPAddress.subnet_id')
    routes = orm.relationship(Route, primaryjoin="Route.subnet_id==Subnet.id",
                              backref='subnet', cascade='delete')
    enable_dhcp = sa.Column(sa.Boolean(), default=False)
    dns_nameservers = orm.relationship(
        DNSNameserver,
        primaryjoin="DNSNameserver.subnet_id==Subnet.id",
        backref='subnet',
        cascade='delete')
    ip_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey("quark_ip_policy.id"))
    # Legacy data
    do_not_use = sa.Column(sa.Boolean(), default=False)


port_ip_association_table = sa.Table(
    "quark_port_ip_address_associations",
    BASEV2.metadata,
    sa.Column("port_id", sa.String(36),
              sa.ForeignKey("quark_ports.id")),
    sa.Column("ip_address_id", sa.String(36),
              sa.ForeignKey("quark_ip_addresses.id")),
    **TABLE_KWARGS)


port_group_association_table = sa.Table(
    "quark_port_security_group_associations",
    BASEV2.metadata,
    sa.Column("port_id", sa.String(36),
              sa.ForeignKey("quark_ports.id")),
    sa.Column("group_id", sa.String(36),
              sa.ForeignKey("quark_security_groups.id")),
    **TABLE_KWARGS)


class SecurityGroupRule(BASEV2, models.HasId, models.HasTenant):
    __tablename__ = "quark_security_group_rule"
    id = sa.Column(sa.String(36), primary_key=True)
    group_id = sa.Column(sa.String(36),
                         sa.ForeignKey("quark_security_groups.id"),
                         nullable=False)
    direction = sa.Column(sa.String(10), nullable=False)
    ethertype = sa.Column(sa.String(4), nullable=False)
    port_range_max = sa.Column(sa.Integer(), nullable=True)
    port_range_min = sa.Column(sa.Integer(), nullable=True)
    protocol = sa.Column(sa.Integer(), nullable=True)
    remote_ip_prefix = sa.Column(sa.String(22), nullable=True)
    remote_group_id = sa.Column(sa.String(36), nullable=True)


class SecurityGroup(BASEV2, models.HasId):
    __tablename__ = "quark_security_groups"
    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255), nullable=False)
    description = sa.Column(sa.String(255), nullable=False)
    join = "SecurityGroupRule.group_id==SecurityGroup.id"
    rules = orm.relationship(SecurityGroupRule, backref='group',
                             cascade='delete',
                             primaryjoin=join)
    tenant_id = sa.Column(sa.String(255), index=True)


class Port(BASEV2, models.HasTenant, models.HasId):
    __tablename__ = "quark_ports"
    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255), index=True)
    admin_state_up = sa.Column(sa.Boolean(), default=True)
    network_id = sa.Column(sa.String(36), sa.ForeignKey("quark_networks.id"),
                           nullable=False)

    backend_key = sa.Column(sa.String(36), nullable=False)
    mac_address = sa.Column(sa.BigInteger())
    device_id = sa.Column(sa.String(255), nullable=False, index=True)
    device_owner = sa.Column(sa.String(255))
    bridge = sa.Column(sa.String(255))

    @declarative.declared_attr
    def ip_addresses(cls):
        primaryjoin = cls.id == port_ip_association_table.c.port_id
        secondaryjoin = (port_ip_association_table.c.ip_address_id ==
                         IPAddress.id)
        return orm.relationship(IPAddress, primaryjoin=primaryjoin,
                                secondaryjoin=secondaryjoin,
                                secondary=port_ip_association_table,
                                backref="ports",
                                order_by='IPAddress.allocated_at')

    @declarative.declared_attr
    def security_groups(cls):
        primaryjoin = cls.id == port_group_association_table.c.port_id
        secondaryjoin = (port_group_association_table.c.group_id ==
                         SecurityGroup.id)
        return orm.relationship(SecurityGroup, primaryjoin=primaryjoin,
                                secondaryjoin=secondaryjoin,
                                secondary=port_group_association_table,
                                backref="ports")

# Indices tailored specifically to get_instance_nw_info calls from nova
sa.Index("idx_ports_1", Port.__table__.c.device_id, Port.__table__.c.tenant_id)
sa.Index("idx_ports_2", Port.__table__.c.device_owner,
         Port.__table__.c.network_id)
sa.Index("idx_ports_3", Port.__table__.c.tenant_id)


class MacAddress(BASEV2, models.HasTenant):
    __tablename__ = "quark_mac_addresses"
    __table_args__ = (sa.UniqueConstraint("mac_address_range_id", "address"),
                      TABLE_KWARGS)
    address = sa.Column(sa.BigInteger(), primary_key=True)
    mac_address_range_id = sa.Column(
        sa.String(36),
        sa.ForeignKey("quark_mac_address_ranges.id", ondelete="CASCADE"),
        nullable=False)
    deallocated = sa.Column(sa.Boolean(), index=True)
    deallocated_at = sa.Column(sa.DateTime(), index=True)
    orm.relationship(Port, backref="mac_address")


class MacAddressRange(CIDRMixin, BASEV2, models.HasId):
    CIDR_WIDTH = 48

    __tablename__ = "quark_mac_address_ranges"
    address = sa.Column(custom_types.MACAddress, nullable=False)
    prefix = sa.Column(sa.Integer, nullable=False)
    allocated_macs = orm.relationship(MacAddress,
                                      primaryjoin='and_(MacAddressRange.id=='
                                      'MacAddress.mac_address_range_id, '
                                      'MacAddress.deallocated!=1)',
                                      backref="mac_address_range")

    @classmethod
    def _split_cidr(cls, cidr):
        if isinstance(cidr, (tuple, list)):
            return netaddr.EUI(cidr[0]), cidr[1]

        address, prefix = cidr.split('/')

        address = address.replace(':', '').replace('-', '')
        address = int(address, 16)
        prefix = int(prefix)

        # NOTE(jkoelker) Compute the IAB Mask from the prefix
        #                The first part turns on all bits, then turn off
        #                the exactly PREFIX bits
        iab_mask = ((1 << cls.CIDR_WITH) - 1) ^ ((1 << prefix) - 1)

        # NOTE(jkoelker) Combine the base address with the computed
        #                mask to make sure the proper bits are off.
        #                This allows an arbitrary address to be passed in
        #                and the correct base address will be calulated.
        return netaddr.EUI(address & iab_mask), cidr.prefixlen


class IPPolicy(BASEV2, models.HasId, models.HasTenant):
    __tablename__ = "quark_ip_policy"
    networks = orm.relationship(
        "Network",
        primaryjoin="IPPolicy.id==Network.ip_policy_id",
        backref="ip_policy")
    subnets = orm.relationship(
        "Subnet",
        primaryjoin="IPPolicy.id==Subnet.ip_policy_id",
        backref="ip_policy")
    exclude = orm.relationship(
        "IPPolicyCIDR",
        primaryjoin="IPPolicy.id==IPPolicyCIDR.ip_policy_id",
        backref="ip_policy")
    name = sa.Column(sa.String(255), nullable=True)
    description = sa.Column(sa.String(255), nullable=True)

    @staticmethod
    def get_ip_policy_cidrs(subnet):
        ip_policy = subnet["ip_policy"] or {}

        subnet_cidr = netaddr.IPNetwork(subnet["cidr"])
        network_ip = subnet_cidr.network
        broadcast_ip = subnet_cidr.broadcast
        prefix_len = '32' if subnet_cidr.version == 4 else '128'
        default_policy_cidrs = ["%s/%s" % (network_ip, prefix_len),
                                "%s/%s" % (broadcast_ip, prefix_len)]
        ip_policy_cidrs = []
        ip_policies = ip_policy.get("exclude", [])
        if ip_policies:
            ip_policy_cidrs = [ip_policy_cidr.cidr
                               for ip_policy_cidr in ip_policies]

        ip_policy_cidrs = ip_policy_cidrs + default_policy_cidrs

        ip_set = netaddr.IPSet(ip_policy_cidrs)

        return ip_set & netaddr.IPSet([subnet_cidr])


class IPPolicyCIDR(CIDRMixin, BASEV2, models.HasId):
    __tablename__ = "quark_ip_policy_cidrs"
    ip_policy_id = sa.Column(sa.String(36), sa.ForeignKey(
        "quark_ip_policy.id", ondelete="CASCADE"))
    address = sa.Column(custom_types.INET, nullable=False)
    prefix = sa.Column(sa.Integer, nullable=False)


class Network(BASEV2, models.HasId):
    __tablename__ = "quark_networks"
    name = sa.Column(sa.String(255))
    ports = orm.relationship(Port, backref='network')
    subnets = orm.relationship(Subnet, backref='network')
    ip_policy_id = sa.Column(sa.String(36),
                             sa.ForeignKey("quark_ip_policy.id"))
    network_plugin = sa.Column(sa.String(36))
    ipam_strategy = sa.Column(sa.String(255))
    tenant_id = sa.Column(sa.String(255), index=True)
