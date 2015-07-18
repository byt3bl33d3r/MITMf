# Copyright (c) 2014-2016 Moxie Marlinspike, Marcello Salvati
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

class DnsCache:    

	'''
	The DnsCache maintains a cache of DNS lookups, mirroring the browser experience.
	'''

	_instance          = None

	def __init__(self):
		self.customAddress = None
		self.cache = {}

	@staticmethod
	def getInstance():
		if DnsCache._instance == None:
			DnsCache._instance = DnsCache()

		return DnsCache._instance

	def cacheResolution(self, host, address):
		self.cache[host] = address

	def getCachedAddress(self, host):
		if host in self.cache:
			return self.cache[host]

		return None
