from plugins.plugin import Plugin


class CacheKill(Plugin):
    name = "CacheKill"
    optname = "cachekill"
    desc = "Kills page caching by modifying headers"
    implements = ["handleHeader", "connectionMade"]
    has_opts = True
    bad_headers = ['if-none-match', 'if-modified-since']

    def add_options(self, options):
        options.add_argument("--preserve-cookies", action="store_true", help="Preserve cookies (will allow caching in some situations).")

    def handleHeader(self, request, key, value):
        '''Handles all response headers'''
        request.client.headers['Expires'] = "0"
        request.client.headers['Cache-Control'] = "no-cache"

    def connectionMade(self, request):
        '''Handles outgoing request'''
        request.headers['Pragma'] = 'no-cache'
        for h in self.bad_headers:
            if h in request.headers:
                request.headers[h] = ""
