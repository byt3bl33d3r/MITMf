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

from core.logger import logger
from core.proxyplugins import ProxyPlugins
from scapy.all import get_if_addr, get_if_hwaddr, get_working_if

formatter = logging.Formatter("%(asctime)s [Utils] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("Utils", formatter)

def shutdown(message=None):
    for plugin in ProxyPlugins().plugin_list:
        plugin.on_shutdown()
    sys.exit(message)

def set_ip_forwarding(value):
    log.debug("Setting ip forwarding to {}".format(value))
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
        file.write(str(value))
        file.close()

def get_iface():
    iface = get_working_if()
    log.debug("Interface {} seems to be up and running")
    return iface

def get_ip(interface):
    try:
        ip_address = get_if_addr(interface)
        if (ip_address == "0.0.0.0") or (ip_address is None):
            shutdown("Interface {} does not have an assigned IP address".format(interface))

        return ip_address
    except Exception as e:
        shutdown("Error retrieving IP address from {}: {}".format(interface, e))

def get_mac(interface):
    try:
        mac_address = get_if_hwaddr(interface)
        return mac_address
    except Exception as e:
        shutdown("Error retrieving MAC address from {}: {}".format(interface, e))

class iptables:

    dns     = False
    http    = False
    smb     = False
    nfqueue = False

    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def flush(self):
        log.debug("Flushing iptables")
        os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
        self.dns  = False
        self.http = False
        self.smb  = False
        self.nfqueue = False

    def HTTP(self, http_redir_port):
        log.debug("Setting iptables HTTP redirection rule from port 80 to {}".format(http_redir_port))
        os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port {}'.format(http_redir_port))
        self.http = True

    def DNS(self, dns_redir_port):
        log.debug("Setting iptables DNS redirection rule from port 53 to {}".format(dns_redir_port))
        os.system('iptables -t nat -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port {}'.format(dns_redir_port))
        self.dns = True

    def SMB(self, smb_redir_port):
        log.debug("Setting iptables SMB redirection rule from port 445 to {}".format(smb_redir_port))
        os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 445 -j REDIRECT --to-port {}'.format(smb_redir_port))
        self.smb = True

    def NFQUEUE(self):
        log.debug("Setting iptables NFQUEUE rule")
        os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')
        self.nfqueue = True