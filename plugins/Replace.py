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
		self.search_str = options.search_str
		self.replace_str = options.replace_str
		self.regex_file = options.regex_file

		if self.options.keep_cache:
			self.implements.remove("handleHeader")
			self.implements.remove("connectionMade")

		if (self.search_str==self.replace_str==None or self.search_str==self.replace_str=="") and self.regex_file is None:
			print "[*] Please provide a search and replace string or a regex file"
			quit()

		self.ctable = {}
		self.dtable = {}
		self.mime = "text/html"
		
		print "[*] Replace plugin online"

	def handleResponse(self,request,data):
		ip,hn,mime = self._get_req_info(request)

		if self._should_replace(ip,hn,mime):

			# Did the user provide us a search and replace str?
			if self.search_str==self.replace_str!=None and self.search_str==self.replace_str!="":
				data = data.replace(self.search_str, self.replace_str)
				logging.info("%s [%s] Replaced '%s' with '%s'" % (request.client.getClientIP(), request.headers['host'], self.search_str, self.replace_str))

			# DI the user provide us with a regex file?
			if self.regex_file is not None:
				for line in self.regex_file:
					replaceRegex = line.split("\t")
					try:
						data = re.sub(replaceRegex[0], replaceRegex[1], data)

						logging.info("%s [%s] Replaced '%s' with '%s'" % (request.client.getClientIP(), request.headers['host'], replaceRegex[0], replaceRegex[1]))
					except Exception, e:
						logging.error("%s [%s] Your provided regex (%s) or replace value (%s) is empyt or invalid. Please debug your provided regex(es)" % (request.client.getClientIP(), request.headers['host'], replaceRegex[0], replaceRegex[1]))

			self.ctable[ip] = time.time()
			self.dtable[ip+hn] = True

			return {'request':request,'data':data}
		
		return

	def add_options(self,options):
		options.add_argument("--replace-str",type=str,help="String you would like to replace.")
		options.add_argument("--search-str",type=str,help="String you would like to replace --replace-str with. Default: '' (empty string)")
		options.add_argument("--regex-file",type=file,help="Load file with regexes. File format: <regex1>[tab]<regex2>[new-line]")
		options.add_argument("--keep-cache",action="store_true",help="Don't kill the server/client caching.")

	def _should_replace(self,ip,hn,mime):
		return mime.find(self.mime)!=-1
			
	def _get_req_info(self,request):
		ip = request.client.getClientIP()
		hn = request.client.getRequestHostname()
		mime = request.client.headers['Content-Type']

		return (ip,hn,mime)
