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
import sys
import tornado.ioloop
import tornado.web
import threading

from core.configwatcher import ConfigWatcher

tornado_logger = logging.getLogger("tornado")
tornado_logger.propagate = False
formatter = logging.Formatter("%(asctime)s [HTTPserver] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
fileHandler = logging.FileHandler("./logs/mitmf.log")
streamHandler = logging.StreamHandler(sys.stdout)
fileHandler.setFormatter(formatter)
streamHandler.setFormatter(formatter)
tornado_logger.addHandler(fileHandler)
tornado_logger.addHandler(streamHandler)

class HTTPServer(ConfigWatcher):

    _instance = None
    application = tornado.web.Application([])
    http_port = int(ConfigWatcher.config["MITMf"]["HTTP"]["port"])

    @staticmethod
    def getInstance():
        if HTTPServer._instance == None:
            HTTPServer._instance = HTTPServer()

        return HTTPServer._instance

    def addHandler(self, urlregex, handler, vhost=''):
        self.application.add_handlers(vhost, [(urlregex, handler)])

    def addStaticPathHandler(self, urlregex, path, vhost=''):
        self.application.add_handlers(vhost, [(urlregex, {"static_path": path})])

    def resetApplication(self):
        self.application = tornado.web.Application([])

    def parseConfig(self):
        for url,path in self.config['MITMf']['HTTP']['Paths'].iteritems():
            self.addStaticPathHandler(url, path)

    def onConfigChange(self):
        self.resetApplication()
        self.parseConfig()

    def start(self):
        self.parseConfig()
        self.application.listen(self.http_port)

        t = threading.Thread(name='HTTPserver', target=tornado.ioloop.IOLoop.instance().start)
        t.setDaemon(True)
        t.start()

class HTTPHandler(tornado.web.RequestHandler):
    def get(self):
        raise HTTPError(405)

    def post(self):
        raise HTTPError(405)