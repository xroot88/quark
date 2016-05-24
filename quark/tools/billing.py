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

"""Calculations for different cases for additional IP billing
See notes in quark/billing.py for more details.
"""

import sys

from neutron.common import config
from neutron import context as neutron_context

from oslo_config import cfg
from oslo_log import log as logging

from pprint import pprint as pp
from quark import billing
from quark.db import models


def main():
    if len(sys.argv) < 3:
        print 'Usage: {0} hour minute [--notify=true]'.format(sys.argv[0])
        print 'by default it won\'t notify billing unless \'--notify=true\''
        print 'is specified'
        print 'if \'--notify=true\' is not specified, the script prints'
        print 'the messages to stdout and exits'
        print 'Ex: "{0} 0 0 --notify=true"'.format(sys.argv[0])
        print 'for a period starting at midnight and send billing msgs'
        return 1
    hour = int(sys.argv[1])
    minute = int(sys.argv[2])
    # Read the config file and get the admin context
    LOG = logging.getLogger(__name__)
    CONF = cfg.CONF
    config_opts = ['--config-file', '/etc/neutron/neutron.conf']
    config.init(config_opts)
    config.setup_logging()
    context = neutron_context.get_admin_context()

    ##billing.make_case2(context)

    # A query to get all IPAddress objects from the db
    query = context.session.query(models.IPAddress)

    (period_start, period_end) = billing.calc_periods(hour, minute)

    full_day_ips = billing.build_full_day_ips(query,
                                              period_start,
                                              period_end)
    partial_day_ips = billing.build_partial_day_ips(query,
                                                    period_start,
                                                    period_end)

    if len(sys.argv) > 3 and sys.argv[3] == '--notify=true':
        print '==================== Full Day ============================='
        for ipaddress in full_day_ips:
            print 'start: {}, end: {}'.format(period_start, period_end)
            payload = billing.build_payload(ipaddress,
                                            'ip.exists',
                                            start_time=period_start,
                                            end_time=period_end)
            billing.do_notify(context,
                              'ip.exists',
                              payload)
        print '==================== Part Day ============================='
        for ipaddress in partial_day_ips:
            print 'start: {}, end: {}'.format(period_start, period_end)
            payload = billing.build_payload(ipaddress,
                                            'ip.exists',
                                            start_time=ipaddress.allocated_at,
                                            end_time=period_end)
            billing.do_notify(context,
                              'ip.exists',
                              payload)
    else:
        print 'Case 1 payloads ({}):\n'.format(len(full_day_ips))
        for ipaddress in full_day_ips:
            pp(billing.build_payload(ipaddress,
                                     'ip.exists',
                                     start_time=period_start,
                                     end_time=period_end))

        print '\n=====================================================\n'

        print 'Case 2 payloads ({}):\n'.format(len(partial_day_ips))
        for ipaddress in partial_day_ips:
            pp(billing.build_payload(ipaddress,
                                     'ip.exists',
                                     start_time=ipaddress.allocated_at,
                                     end_time=period_end))

if __name__ == '__main__':
    main()
