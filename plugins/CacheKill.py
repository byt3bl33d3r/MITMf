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

import logging
from plugins.plugin import Plugin

mitmf_logger = logging.getLogger("mitmf")

class CacheKill(Plugin):
    name        = "CacheKill"
    optname     = "cachekill"
    desc        = "Kills page caching by modifying headers"
    version     = "0.1"

    def initialize(self, options):
        self.bad_headers = ['if-none-match', 'if-modified-since']

    def serverHeaders(self, response, request):
        '''Handles all response headers'''
        response.headers['Expires'] = "0"
        response.headers['Cache-Control'] = "no-cache"

    def clientRequest(self, request):
        '''Handles outgoing request'''
        request.headers['pragma'] = 'no-cache'
        for header in self.bad_headers:
            if header in request.headers:
                del request.headers[header]