from plugins.plugin import Plugin
from libs.sslstrip.URLMonitor import URLMonitor
import sys

class HSTSbypass(Plugin):
	name     = 'SSLstrip+'
	optname  = 'hsts'
	desc     = 'Enables SSLstrip+ for partial HSTS bypass'
	version  = "0.2"
	has_opts = False
	req_root = False

	def initialize(self, options):
		self.options = options

		try:
			config = options.configfile['SSLstrip+']
		except Exception, e:
			sys.exit("[-] Error parsing config for SSLstrip+: " + str(e))

		URLMonitor.getInstance().setHstsBypass(config)
