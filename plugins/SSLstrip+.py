from plugins.plugin import Plugin
from libs.sslstrip.URLMonitor import URLMonitor
import sys

class HSTSbypass(Plugin):
	name    = 'SSLstrip+'
	optname = 'hsts'
	desc    = 'Enables SSLstrip+ for partial HSTS bypass'
	has_opts = False

	def initialize(self, options):
		self.options = options

		try:
			config = options.configfile['SSLstrip+']
		except Exception, e:
			sys.exit("[-] Error parsing config for SSLstrip+: " + str(e))

		print "[*] SSLstrip+ plugin online"
		URLMonitor.getInstance().setHstsBypass(config)
