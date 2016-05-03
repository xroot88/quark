# Copyright (c) 2016 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# This API adds audit functionality to quark.
# The new attributes are specified here.
#

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper

RESOURCE_NAME = 'audit'

RESOURCE_ATTRIBUTE_MAP = {
    'netinfo_instances': {
        'instance_id': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True
        }
    },
    'netinfo_tenants': {
        'tenant_id': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True
        }
    },
    'billinfo_tenants': {
        'tenant_id': {
            'allow_post': False,
            'allow_put': False,
            'is_visible': True
        }
    }
}


class Audit(extensions.ExtensionDescriptor):
    """The name of the class must match the file name"""
    @classmethod
    def get_name(cls):
        return 'Quark %s' % RESOURCE_NAME

    @classmethod
    def get_alias(cls):
        return RESOURCE_NAME

    @classmethod
    def get_description(cls):
        return 'Quark audit extension.'

    @classmethod
    def get_updated(cls):
        return '2016-05-01T00:00:00-00:00'

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/network/ext/"
                "audit/api/v2.0")

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources"""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   None)
