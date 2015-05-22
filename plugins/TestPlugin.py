from plugins.plugin import Plugin
from core.servers.http.HTTPServer import HTTPServer
import tornado.web

class TestPlugin(Plugin):
    name     = "testplugin"
    optname  = "test"
    desc     = "Plugin to test dynamically configuring the internal web server"
    version  = "0.1"
    has_opts = False

    def initialize(self, options):
        HTTPServer.getInstance().addHandler(r"/test/(.*)", MainHandler)

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        print self.request
        self.write("Hello World!")
