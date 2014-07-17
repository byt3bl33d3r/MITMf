import os,subprocess,logging,time,re
import argparse
from plugins.plugin import Plugin
from plugins.CacheKill import CacheKill

class Replace(CacheKill,Plugin):
    name = "Replace"
    optname = "replace"
    implements = ["handleResponse","handleHeader","connectionMade"]
    has_opts = True
    desc = "Replace arbitrary content in HTML content"
    
    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
		self.match_str = options.match_str
		self.replace_str = options.replace_str

        if self.options.preserve_cache:
            self.implements.remove("handleHeader")
            self.implements.remove("connectionMade")

        self.ctable = {}
        self.dtable = {}
        self.mime = "text/html"
        
		print "[*] Replace plugin online"

    def handleResponse(self,request,data):
        ip,hn,mime = self._get_req_info(request)

        if self._should_replace(ip,hn,mime) and (not self.replace_str==self.search_str==None) and (not self.search_str==""):
            data = self.replace(self.search_str, self.replace_str)

            self.ctable[ip] = time.time()
            self.dtable[ip+hn] = True

            logging.info("%s [%s] Replaced '%s' with '%s'" % (request.client.getClientIP(), request.headers['host'], self.match_str, self.replace_str))

            return {'request':request,'data':data}
        
		return

    def add_options(self,options):
        options.add_argument("--replace-str",type=str,default="",help="String you would like to replace.")
        options.add_argument("--search-str",type=str,default="",help="String you would like to replace --replace-str with. Default: '' (empty string)")
        options.add_argument("--preserve-cache",action="store_true",help="Don't kill the server/client caching.")

    def _should_replace(self,ip,hn,mime):
        return mime.find(self.mime)!=-1
            
    def _get_req_info(self,request):
        ip = request.client.getClientIP()
        hn = request.client.getRequestHostname()
        mime = request.client.headers['Content-Type']
        return (ip,hn,mime)
