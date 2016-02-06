'''
The base plugin class. This shows the various methods that
can get called during the MITM attack.
'''
import argparse
import logging

class Plugin(object):
    name    = "Example Plugin"
    optname = "example"
    desc    = ""
    version = "0.0"

    def __init__(self, parser=None):
        '''Optionally Passed the options namespace'''
        if parser:
            if self.desc:
                sgroup = parser.add_argument_group(self.name, self.desc)
            else:
                sgroup = parser.add_argument_group(self.name,'Options for the {} plugin'.format(self.name))

            sgroup.add_argument('--{}'.format(self.optname), action='store_true',help='Load plugin {}'.format(self.name))

            self.options(sgroup)

    def initialize(self, context):
        '''Called when plugin is started'''
        pass

    def shutdown(self, context):
        '''This will be called when shutting down'''
        pass

    def request(self, context, flow):
        pass

    def responseheaders(self, context, flow):
        pass

    def response(self, context, flow):
        pass

    def options(self, options):
        '''Add your options to the options parser'''
        pass
