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

class CacheKill(Plugin):
    name        = "CacheKill"
    optname     = "cachekill"
    desc        = "Kills page caching by modifying headers"
    implements  = ["handleHeader", "connectionMade"]
    bad_headers = ['if-none-match', 'if-modified-since']
    version     = "0.1"
    has_opts    = True

    def add_options(self, options):
        options.add_argument("--preserve-cookies", action="store_true", help="Preserve cookies (will allow caching in some situations).")

    def handleHeader(self, request, key, value):
        '''Handles all response headers'''
        request.client.headers['Expires'] = "0"
        request.client.headers['Cache-Control'] = "no-cache"

    def connectionMade(self, request):
        '''Handles outgoing request'''
        request.headers['Pragma'] = 'no-cache'
        for h in self.bad_headers:
            if h in request.headers:
                request.headers[h] = ""
