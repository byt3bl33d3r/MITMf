# -*- coding: utf-8 -*-

# Copyright (c) 2014-2016 Marcello Salvati
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import os
import logging
import re
import sys
from core.logger import DebugLoggerAdapter

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr, get_if_hwaddr

debug_logger = DebugLoggerAdapter(logging.getLogger('MITMf'), {'source': 'Utils'})

def set_ip_forwarding(value):
    debug_logger.debug('Setting ip forwarding to {}'.format(value))
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
        file.write(str(value))
        file.close()

def get_ip(interface):
    try:
        ip_address = get_if_addr(interface)
        if (ip_address == '0.0.0.0') or (ip_address is None):
            debug_logger.error('{} does not have an assigned ip address'.format(interface))
            sys.exit(1)

        return ip_address
    except Exception as e:
        debug_logger.error('Error retrieving ip address from {}: {}'.format(interface, e))
        sys.exit(1)

def get_mac(interface):
    try:
        mac_address = get_if_hwaddr(interface)
        return mac_address
    except Exception as e:
        debug_logger.error('Error retrieving mac address from {}: {}'.format(interface, e))
