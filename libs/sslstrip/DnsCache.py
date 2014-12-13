import logging

class DnsCache:    

	'''
	The DnsCache maintains a cache of DNS lookups, mirroring the browser experience.
	'''

	_instance          = None

	def __init__(self):
		self.customAddress = None
		self.cache = {}

	def cacheResolution(self, host, address):
		self.cache[host] = address

	def getCachedAddress(self, host):
		if host in self.cache:
			return self.cache[host]

		return None

	def getInstance():
		if DnsCache._instance == None:
			DnsCache._instance = DnsCache()

		return DnsCache._instance

	def setCustomRes(self, host, ip_address=None):
		if ip_address is not None:
			self.cache[host] = ip_address
			logging.debug("DNS entry set: %s -> %s" %(host, ip_address))
		else:
			if self.customAddress is not None:
				self.cache[host] = self.customAddress

	def setCustomAddress(self, ip_address):
		self.customAddress = ip_address

	getInstance = staticmethod(getInstance)
