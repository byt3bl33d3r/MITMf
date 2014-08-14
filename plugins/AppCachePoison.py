from plugins.plugin import Plugin
from sslstrip.ResponseTampererFactory import ResponseTampererFactory
#import threading


class AppCachePlugin(Plugin):
    name = "App Cache Poison"
    optname = "app"
    desc = "Performs App Cache Poisoning attacks"
    has_opts = True

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.config_file = options.tampercfg

        if self.config_file is None:
            self.config_file = "./config_files/app_cache_poison.cfg"

        print "[*] App Cache Poison plugin online"
        ResponseTampererFactory.buildTamperer(self.config_file)

    def add_options(self, options):
        options.add_argument("--tampercfg", type=file, help="Specify a config file")
