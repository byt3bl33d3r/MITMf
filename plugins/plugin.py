'''
The base plugin class. This shows the various methods that
can get called during the MITM attack. 
'''

class Plugin(object):
    name = "Generic plugin"
    optname = "generic"
    desc = ""
    implements = []
    has_opts = False
    def __init__(self):
        '''Called on plugin instantiation. Probably don't need this'''
        pass
    def initialize(self,options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options

    def add_options(options):
        '''Add your options to the options parser'''
        raise NotImplementedError

    def handleHeader(self,request,key,value):
        '''Handles all response headers'''
        raise NotImplementedError

    def connectionMade(self,request):
        '''Handles outgoing request'''
        raise NotImplementedError
    
    def handleResponse(self,request,data):
        '''
            Handles all non-image responses by default. See Upsidedownternet
            for how to get images   
        '''
        raise NotImplementedError

    def finish(self):
        '''This will be called when shutting down'''
        pass
