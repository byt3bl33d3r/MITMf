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

"""

Plugin by @rubenthijssen

"""

import sys
import logging
import time
import re
from plugins.plugin import Plugin
from plugins.CacheKill import CacheKill
from core.sergioproxy.ProxyPlugins import ProxyPlugins

mitmf_logger = logging.getLogger("mitmf")

class Replace(Plugin):
	name       = "Replace"
	optname    = "replace"
	desc       = "Replace arbitrary content in HTML content"
	version    = "0.2"
	has_opts   = False

	def initialize(self, options):
		self.options = options

		self.ctable = {}
		self.dtable = {}
		self.mime = "text/html"

	def serverResponse(self, response, request, data):
		ip, hn, mime = self._get_req_info(response)

		if self._should_replace(ip, hn, mime):

			# Did the user provide us with a regex file?
			for rulename, regexs in self.config['Replace'].iteritems():
				for regex1,regex2 in regexs.iteritems():
					if re.search(regex1, data):
						try:
							data = re.sub(regex1, regex2, data)

							mitmf_logger.info("{} [{}] Host: {} Occurances matching '{}' replaced with '{}' according to rule '{}'".format(ip, self.name, hn, regex1, regex2, rulename))
						except Exception:
							mitmf_logger.error("{} [{}] Your provided regex ({}) or replace value ({}) is empty or invalid. Please debug your provided regex(es) in rule '{}'" % (ip, hn, regex1, regex2, rulename))

			self.ctable[ip] = time.time()
			self.dtable[ip+hn] = True

		return {'response': response, 'request': request, 'data': data}

	def _should_replace(self, ip, hn, mime):
		return mime.find(self.mime) != -1

	def _get_req_info(self, response):
		ip = response.getClientIP()
		hn = response.getRequestHostname()
		mime = response.headers['Content-Type']

		return (ip, hn, mime)
