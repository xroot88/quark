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

"""Calculations for different cases for additional IP billing
A - allocated
D - deallocated
| - start or end of the billing period, typically 24 hrs

A |     | D
  | A   | D
A | D   |
  | A D |

---IP CURRENTLY ALLOCATED=has tenant_id (send usage at end of period)---
case 1 (allocated before period began, deallocated after period ended)
  send usage as 24 hours
case 2 (allocated during period, deallocated after period ended)
  send usage as timedelta(period_end - allocated_at)

---IP DEALLOCATED DURING PERIOD (send usage at deallocation time)---
case 3 (allocated before period began, deallocated during period)
  send usage as timedelta(deallocated_at - period_start)
case 4 (allocated during period, deallocated during period)
  send usage as timedelta(deallocated_at - allocated_at)

NOTE: notifications are issued at these times:
    case1 and case2 - this script runs nightly and processes the entries
    case3 and case4 - the notifications are sent immediately when the ip
                      is deallocated
NOTE: assumes that the beginning of a billing cycle is midnight.
"""

import datetime
import sys

from neutron.common import config
from neutron.common import rpc as n_rpc
from neutron import context as neutron_context

from oslo_config import cfg
from oslo_log import log as logging

from sqlalchemy import and_, or_, null

from quark.db import models

LOG = logging.getLogger(__name__)

PUBLIC_NETWORK_ID = u'00000000-0000-0000-0000-000000000000'

EVENT_TYPE_2_CLOUDFEEDS = {
    'ip.exists':        'USAGE',
    'ip.add':           'CREATE',
    'ip.delete':        'DELETE',
    'ip.associate':     'UP',
    'ip.disassociate':  'DOWN'
}

def do_notify(context, event_type, payload):
    """Generic Notifier.
    Parameters:
        - `context`: session context
        - `event_type`: the event type to report, i.e. ip.usage
        - `payload`: dict containing the payload to send
    """
    LOG.debug('IP_BILL: notifying {}'.format(payload))

    notifier = n_rpc.get_notifier('network')
    notifier.info(context, event_type, payload)


def notify(context, event_type, ipaddress, send_usage=False):
    """Method to send notifications.
    We must send USAGE when a public IPv4 address is deallocated or a FLIP is
    associated.
    Parameters:
        - `context`: the context for notifier
        - `event_type`: the event type for IP allocate, deallocate, associate,
        disassociate
        - `ipaddress`: the ipaddress object to notify about
    Returns:
        nothing
    Notes: this may live in the billing module
    """
    # First record the timestamp of when the notifier was called
    now = now()

    # Build payloads based on the message type and supply the correct start/end
    # or event times.
    if event_type == 'ip.add':
        # allocated_at is more precise than now(), so we use allocated_at
        payload = build_payload(ipaddress,
                                event_type,
                                event_time=ipaddress.allocated_at)
    elif event_type == 'ip.delete':
        payload = build_payload(ipaddress,
                                event_type,
                                event_time=now)
    elif event_type == 'ip.associate':
        payload = build_payload(ipaddress, event_type, event_time=now)
    elif event_type == 'ip.disassociate':
        payload = build_payload(ipaddress, event_type, event_time=now)
    else:
        LOG.error('IPAM: unknown event_type {}'.format(event_type))
        return

    # Send the notification with the payload
    do_notify(context, event_type, payload)

    # When we deallocate an IP or associate a FLIP we must send
    # a usage message to billing.
    # In other words when we supply end_time we must send USAGE to billing
    # immediately.
    # Our billing period is 24 hrs. If the address was allocated after midnight
    # send the start_time as as. If the address was allocated yesterday, then
    # send midnight as the start_time.
    if send_usage:
        if ipaddress.allocated_at >= midnight_today():
            start_time = ipaddress.allocated_at
        else:
            start_time = midnight_today()
        payload = build_payload(ipaddress,
                                'ip.exists',
                                start_time=start_time,
                                end_time=now)
        do_notify(context, 'ip.exists', payload)


def build_payload(ipaddress,
                  event_type,
                  event_time=None,
                  start_time=None,
                  end_time=None):
    """Method builds a payload out of the passed arguments.
    Parameters:
        `ipaddress`: the models.IPAddress object
        `event_type`: USAGE,CREATE,DELETE,SUSPEND,or UNSUSPEND
        `start_time`: startTime for cloudfeeds
        `end_time`: endTime for cloudfeeds
    Returns a dictionary suitable to notify billing.
    Message types mapping to cloud feeds for references:
        ip.exists       - USAGE
        ip.add          - CREATE
        ip.delete       - DELETE
        ip.associate    - UP
        ip.disassociate  - DOWN
    http://docs-internal-staging.rackspace.com/cloud-feeds/api/v1.0/feeds-publishers-guide/feeds-publishers-guide-latest.pdf
    """
    # This is the common part of all message types
    payload = {
        'event_type': unicode(EVENT_TYPE_2_CLOUDFEEDS[event_type]),
        'tenant_id': int(ipaddress.used_by_tenant_id),
        'ip_address': unicode(ipaddress.address_readable),
        'subnet_id': unicode(ipaddress.subnet_id),
        'network_id': unicode(ipaddress.network_id),
        'public': True if ipaddress.network_id == PUBLIC_NETWORK_ID else False,
        'ip_version': int(ipaddress.version),
        'ip_type': unicode(ipaddress.address_type),
        'id': unicode(ipaddress.id)
    }

    # Depending on the message type add the appropriate fields
    if event_type == 'ip.exists':
        if start_time is None or end_time is None:
            raise ValueError('IP_BILL: {} start_time/end_time cannot be empty'\
                             .format(event_type))
        payload.update({
            'startTime': unicode(convert_timestamp(start_time)),
            'endTime': unicode(convert_timestamp(end_time))
        })
    elif event_type == 'ip.add':
        if event_time is None:
            raise ValueError('IP_BILL: {}: event_time cannot be NULL'\
                             .format(event_type))
        payload.update({
            'eventTime': unicode(convert_timestamp(event_time)),
        })
    elif event_type == 'ip.delete':
        if event_time is None:
            raise ValueError('IP_BILL: {}: event_time cannot be NULL'\
                             .format(event_type))
        payload.update({
            'eventTime': unicode(convert_timestamp(event_time))
        })
    elif event_type == 'ip.associate' or event_type == 'ip.disassociate':
        if event_time is None:
            raise ValueError('IP_BILL: {}: event_time cannot be NULL'\
                             .format(event_type))
        # only pass floating ip addresses through this
        if ipaddress.address_type != 'floating':
            raise ValueError('IP_BILL: {} only valid for floating IPs'.\
                            format(event_type))

        if event_type == 'ip.associate':
            if start_time is None:
                raise ValueError('IP_BILL: start_time is required ' +
                                 'for ip.associate')
            payload.update({
                'eventTime': unicode(convert_timestamp(event_time))
            })
        else: # ip.disassociate
            if end_time is None:
                raise ValueError('IP_BILL: end_time is required ' +
                                 'for ip.disassociate')
            payload.update({
                'eventTime': unicode(convert_timestamp(event_time))
            })
    else:
        raise ValueError('IP_BILL: bad event_type: {}'.format(event_type))

    return payload


def build_full_day_ips(query, period_start, period_end):
    """Method to build an IP list for the case 1 when the IP
    was allocated before the period start and is still allocated
    after the period end.
    This method only looks at public IPv4 addresses.
    """

    # Filter out only IPv4 that have not been deallocated
    ip_list = query.\
            filter(models.IPAddress.version == 4L).\
            filter(models.IPAddress.network_id == PUBLIC_NETWORK_ID).\
            filter(models.IPAddress.used_by_tenant_id != None).\
            filter(models.IPAddress.allocated_at != null()).\
            filter(models.IPAddress.allocated_at < period_start).\
            filter(or_(models.IPAddress._deallocated == False,\
                       models.IPAddress.deallocated_at >= period_end)).all()

    return ip_list


def build_partial_day_ips(query, period_start, period_end):
    """Method to build an IP list for the case 2 when the IP
    was allocated after the period start and is still allocated
    after the period end.
    This method only looks at public IPv4 addresses.
    """

    # Filter out only IPv4 that were allocated after the period start
    # and have not been deallocated before the period end.
    # allocated_at will be set to a date
    ip_list = query.\
            filter(models.IPAddress.version == 4L).\
            filter(models.IPAddress.network_id == PUBLIC_NETWORK_ID).\
            filter(models.IPAddress.used_by_tenant_id != None).\
            filter(and_(models.IPAddress.allocated_at != null(),\
                       models.IPAddress.allocated_at >= period_start,\
                       models.IPAddress.allocated_at < period_end)).\
            filter(or_(models.IPAddress._deallocated == False,\
                       models.IPAddress.deallocated_at == null(),\
                       models.IPAddress.deallocated_at >= period_end)).all()


    return ip_list


def calc_periods(hour=0, minute=0):
    """Returns a tuple of start_period and end_period.
    Assumes that the period is 24-hrs.
    Parameters:
        - `hour`: the hour from 0 to 23 when the period ends
        - `minute`: the minute from 0 to 59 when the period ends
    This method will calculate the end of the period as the closest hour/minute
    going backwards.
    It will also calculate the start of the period as the passed hour/minute
    but 24 hrs ago.
    Example, if we pass 0, 0 - we will get the events from 0:00 midnight of the
    day before yesterday until today's midnight.
    If we pass 2,0 - we will get the start time as 2am of the previous morning
    till 2am of today's morning.
    By default it's midnight.
    """
    # Calculate the time intervals in a usable form
    period_end = datetime.datetime.utcnow().replace(hour=hour,
                                                    minute=minute,
                                                    second=0,
                                                    microsecond=0)
    period_start = period_end - datetime.timedelta(days=1)

    # period end should be slightly before the midnight.
    # hence, we subtract a second
    # this will force period_end to store something like:
    # datetime.datetime(2016, 5, 19, 23, 59, 59, 999999)
    # instead of:
    # datetime.datetime(2016, 5, 20,  0,  0,  0,      0)
    period_end -= datetime.timedelta(seconds=1)

    return (period_start, period_end)


def midnight_from_datetime(ts):
    """Finds the midnight for the ts passed
    """
    return ts.replace(hour=0, minute=0, second=0)


def midnight_today():
    return datetime.datetime.utcnow().replace(hour=0,
                                              minute=0,
                                              second=0)

def get_start_time(ts):
    """If ts is after that day's midnight returns ts
    if ts is prior to that day's midnight returns that day midnight
    We are given a timestamp May 10, 2016, 14:00.
    Period starts at midnight that day, i.e. May 10, 2016, 00:00.
    
    """
    if ts and ts < midnight_today():
        return ts
    # Fall through because ts could be None - return midnight
    return midnight_from_datetime(ts)


def get_end_time(ts):
    """If ts is None, replaces it with utcnow()
    """
    return ts if ts is not None else datetime.datetime.utcnow()


def seconds_since_midnight(ts):
    """Helper method to find how many seconds elapsed since midnight
    that occurred before the timestamp passed.
    Parameters:
        - `ts`: timestamp in datetime format
        Returns:
            seconds elapsed since midnight till ts
    """
    return (ts - ts.replace(hour=0, minute=0, second=0)).seconds

def make_case2(context):
    query = context.session.query(models.IPAddress)
    period_start, period_end = calc_periods()
    ip_list = build_full_day_ips(query, period_start, period_end)
    import random
    ind = random.randint(0,len(ip_list)-1)
    print 'using index {}'.format(ind)
    address = ip_list[ind]
    address.allocated_at = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    context.session.add(address)
    context.session.flush()

def convert_timestamp(ts):
    """Converts the timestamp to a format suitable for Billing.
    Examples of a good timestamp for startTime, endTime, and eventTime:
        '2016-05-20T00:00:00Z'
    Note the trailing 'Z'. Python does not add the 'Z' so we tack it on
    ourselves.
    """
    return ts.isoformat() + 'Z'

def now():
    """Method to get the utcnow without microseconds
    """
    return datetime.datetime.utcnow().replace(microsecond=0)
