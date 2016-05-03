# Copyright 2016 Openstack Foundation
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

from oslo_config import cfg
from oslo_log import log as logging

from quark import plugin_views as v


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def get_netinfo_instances(context,
                          filters,
                          fields,
                          sorts,
                          limit,
                          marker,
                          page_reverse):
    instances = []
    return [v._make_netinfo_instance_dict() for instance in instances]


def get_netinfo_instance(context, id, fields):
    instance = None
    return v._make_netinfo_instance_dict(instance)


def get_netinfo_tenants(context,
                        filters,
                        fields,
                        sorts,
                        limit,
                        marker,
                        page_reverse):
    tenants = []
    return [v._make_netinfo_tenant_dict() for tenant in tenants]


def get_netinfo_tenant(context, id, fields):
    tenant = None
    return v._make_netinfo_tenant_dict(tenant)


def get_billinfo_tenants(context,
                         filters,
                         fields,
                         sorts,
                         limit,
                         marker,
                         page_reverse):
    tenants = []
    return [v._make_billinfo_tenant_dict() for tenant in tenants]


def get_billinfo_tenant(context, id, fields):
    tenant = None
    return v._make_billinfo_tenant_dict(tenant)
