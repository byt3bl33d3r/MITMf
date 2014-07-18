#There probably is a better way of doing this

import logging, re, sys, os
from plugins.plugin import Plugin

class LinkRw(Plugin):
    name = "Link Re-Writer"
    optname = "linkrw"
    implements = ["handleResponse"]
    has_opts = True
    desc = "Rewrites all href attributes to a specified url"
    
    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.url = options.url 

        self.mime = "text/html"

        print "[*] Link Re-Writer plugin online"


    def handleResponse(self, request, data):
        ip,hn,mime = self._get_req_info(request)
        if mime.find(self.mime)!=-1:

            data = self.repl_hrefs(data)
            logging.info("%s [%s] Re-wrote hrefs" % (request.client.getClientIP(), request.headers['host']))
            return {'request':request,'data':data}
        else:
            return

    def add_options(self, options):
        options.add_argument("--url", type=str, help="URL to re-write")
            
    def _get_req_info(self, request):
        ip = request.client.getClientIP()
        hn = request.client.getRequestHostname()
        mime = request.client.headers['Content-Type']
        return (ip,hn,mime)

    def repl_hrefs(self, data):

        regex = [re.compile(r"href=[\'\"]http[s]?://.+[\'\"]", re.I)]
            
        for i,r in enumerate(regex):
            data=re.sub(r, "href=" + self.url, data)
        return data
