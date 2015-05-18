'''
The base plugin class. This shows the various methods that
can get called during the MITM attack. 
'''
from core.configwatcher import ConfigWatcher
import logging

mitmf_logger = logging.getLogger('mitmf')

class Plugin(ConfigWatcher, object):
    name        = "Generic plugin"
    optname     = "generic"
    tree_info   = list()
    desc        = ""
    has_opts    = False

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options

    def startThread(self, options):
        '''Anything that will subclass this function will be a thread, passed the options namespace'''
        return

    def clientRequest(self, request):
        '''
            Handles all outgoing requests, hooks connectionMade()
            request object has the following attributes:

            request.headers => headers in dict format
            request.commad  => HTTP method
            request.post    => POST data
            request.uri     => full URL
            request.path    => path
        '''
        pass

    def serverHeaders(self, response, request):
        '''
            Handles all response headers, hooks handleEndHeaders()
        '''
        pass

    def serverResponse(self, response, request, data):
        '''
            Handles all non-image responses by default, hooks handleResponse() (See Upsidedownternet for how to get images)  
        '''
        return {'response': response, 'request':request, 'data': data}

    def pluginOptions(self, options):
        '''Add your options to the options parser'''
        pass

    def pluginReactor(self, strippingFactory):
        '''This sets up another instance of the reactor on a diffrent port, passed the default factory'''
        pass

    def finish(self):
        '''This will be called when shutting down'''
        pass
