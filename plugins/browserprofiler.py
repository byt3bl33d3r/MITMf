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
import json

from pprint import pformat
from plugins.plugin import Plugin
from plugins.inject import Inject

class BrowserProfiler(Inject, Plugin):
    name       = "BrowserProfiler"
    optname    = "browserprofiler"
    desc       = "Attempts to enumerate all browser plugins of connected clients"
    version    = "0.3"

    def initialize(self, options):
        Inject.initialize(self, options)
        self.js_file = "./core/javascript/plugindetect.js"
        self.output = {}  # so other plugins can access the results

    def request(self, request):
        if (request.command == 'POST') and ('clientprfl' in request.uri):
            request.handle_post_output = True
            self.output = json.loads(request.postData)
            self.output['ip'] = request.client.getClientIP()
            pretty_output = pformat(self.output)
            self.clientlog.info("Got profile:\n{}".format(pretty_output), extra=request.clientInfo)

    def options(self, options):
        pass
