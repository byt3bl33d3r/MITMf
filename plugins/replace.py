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

"""

Original plugin by @rthijssen

"""

import re
from plugins.plugin import Plugin

class Replace(Plugin):
    name       = "Replace"
    optname    = "replace"
    desc       = "Replace arbitrary content in HTML content"
    version    = "0.2"

    def initialize(self, options):
        self.options = options

    def response(self, response, request, data):
        mime = response.responseHeaders.getRawHeaders('Content-Type')[0]
        hn = response.getRequestHostname()

        if "text/html" in mime:

            for rulename, regexs in self.config['Replace'].iteritems():
                for regex1,regex2 in regexs.iteritems():
                    if re.search(regex1, data):
                        try:
                            data = re.sub(regex1, regex2, data)

                            self.clientlog.info("occurances matching '{}' replaced with '{}' according to rule '{}'".format(regex1, regex2, rulename), extra=request.clientInfo)
                        except Exception:
                            self.log.error("Your provided regex ({}) or replace value ({}) is empty or invalid. Please debug your provided regex(es) in rule '{}'".format(regex1, regex2, rulename))

        return {'response': response, 'request': request, 'data': data}
