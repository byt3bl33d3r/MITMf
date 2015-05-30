from plugins.plugin import Plugin
from core.servers.http.HTTPServer import HTTPServer, HTTPHandler

class TestPlugin(Plugin):
    name     = "testplugin"
    optname  = "test"
    desc     = "Plugin to test dynamically configuring the internal web server"
    version  = "0.1"
    has_opts = False

    def initialize(self, options):
        HTTPServer.getInstance().addHandler(r"/test/.*", WebServer)

class WebServer(HTTPHandler):
    def get(self):
        self.write("It works MOFO!")