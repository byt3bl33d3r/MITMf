'''
The base plugin class. This shows the various methods that
can get called during the MITM attack. 
'''
from core.configwatcher import ConfigWatcher
import logging

mitmf_logger = logging.getLogger('mitmf')

class Plugin(ConfigWatcher, object):
    name       = "Generic plugin"
    optname    = "generic"
    desc       = ""
    implements = []
    has_opts   = False

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options

    def startThread(self, options):
        '''Anything that will subclass this function will be a thread'''
        return

    def add_options(options):
        '''Add your options to the options parser'''
        raise NotImplementedError

    def handleHeader(self, request, key, value):
        '''Handles all response headers'''
        raise NotImplementedError

    def connectionMade(self, request):
        '''Handles outgoing request'''
        raise NotImplementedError

    def pluginReactor(self, strippingFactory):
        '''This sets up another instance of the reactor on a diffrent port'''
        pass

    def handleResponse(self, request, data):
        '''
            Handles all non-image responses by default. See Upsidedownternet
            for how to get images   
        '''
        raise NotImplementedError

    def finish(self):
        '''This will be called when shutting down'''
        pass
