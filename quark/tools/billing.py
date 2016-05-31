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

from pprint import pprint as pp
from quark import billing
from quark.db import models


def main():
    if len(sys.argv) < 3:
        sys.stderr.write('Usage: {0}'.format(sys.argv[0]))
        sys.stderr.write(' hour minute [--notify=true]\n')
        sys.stderr.write('by default it won\'t notify billing unless')
        sys.stderr.write('\'--notify=true\' is specified')
        sys.stderr.write('if \'--notify=true\' is not specified,')
        sys.stderr.write(' the script prints')
        sys.stderr.write(' the messages to stdout and exits\n')
        sys.stderr.write('Ex: "{0} 0 0 --notify=true"'.format(sys.argv[0]))
        sys.stderr.write(' for a period starting at midnight')
        sys.stderr.write(' and send billing msgs\n')
        return 1
    hour = int(sys.argv[1])
    minute = int(sys.argv[2])
    # Read the config file and get the admin context
    config_opts = ['--config-file', '/etc/neutron/neutron.conf']
    config.init(config_opts)
    config.setup_logging()
    context = neutron_context.get_admin_context()

    # Here one can make case 2 entry in the db
    # billing.make_case2(context)

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
        # '==================== Full Day ============================='
        for ipaddress in full_day_ips:
            sys.stdout.write('start: {}, end: {}'.format(period_start,
                                                         period_end))
            payload = billing.build_payload(ipaddress,
                                            'ip.exists',
                                            start_time=period_start,
                                            end_time=period_end)
            billing.do_notify(context,
                              'ip.exists',
                              payload)
        # '==================== Part Day ============================='
        for ipaddress in partial_day_ips:
            sys.stdout.write('start: {}, end: {}'.format(period_start,
                                                         period_end))
            payload = billing.build_payload(ipaddress,
                                            'ip.exists',
                                            start_time=ipaddress.allocated_at,
                                            end_time=period_end)
            billing.do_notify(context,
                              'ip.exists',
                              payload)
    else:
        sys.stdout.write('Case 1 ({}):\n'.format(len(full_day_ips)))
        for ipaddress in full_day_ips:
            pp(billing.build_payload(ipaddress,
                                     'ip.exists',
                                     start_time=period_start,
                                     end_time=period_end))

        sys.stdout.write('\n===============================================\n')

        sys.stdout.write('Case 2 ({}):\n'.format(len(partial_day_ips)))
        for ipaddress in partial_day_ips:
            pp(billing.build_payload(ipaddress,
                                     'ip.exists',
                                     start_time=ipaddress.allocated_at,
                                     end_time=period_end))

if __name__ == '__main__':
    main()
