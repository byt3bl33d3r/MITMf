from plugins.plugin import Plugin
from libs.sslstripkoto.ResponseTampererFactory import ResponseTampererFactory
#import threading


class AppCachePlugin(Plugin):
    name = "App Cache Poison"
    optname = "appoison"
    desc = "Performs App Cache Poisoning attacks"
    has_opts = False

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.config_file = "./config/app_cache_poison.cfg"
        
        print "[*] App Cache Poison plugin online"
        ResponseTampererFactory.buildTamperer(self.config_file)
