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
import argparse

from core.configwatcher import ConfigWatcher
from core.logger import logger

class Plugin(ConfigWatcher):
    name        = "Generic plugin"
    optname     = "generic"
    tree_info   = []
    desc        = ""
    version     = "0.0"

    def __init__(self, parser):
        '''Passed the options namespace'''

        if self.desc:
            sgroup = parser.add_argument_group(self.name, self.desc)
        else:
            sgroup = parser.add_argument_group(self.name,"Options for the '{}' plugin".format(self.name))

        sgroup.add_argument("--{}".format(self.optname), action="store_true",help="Load plugin '{}'".format(self.name))

        self.options(sgroup)

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options

    def request(self, request):
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

    def responseheaders(self, response, request):
        '''
            Handles all response headers, hooks handleEndHeaders()
        '''
        pass

    def responsestatus(self, request, version, code, message):
        '''
            Handles server response HTTP version, code and message
        '''
        return {"request": request, "version": version, "code": code, "message": message}

    def response(self, response, request, data):
        '''
            Handles all non-image responses by default, hooks handleResponse() (See Upsidedownternet for how to get images)  
        '''
        return {'response': response, 'request':request, 'data': data}

    def on_config_change(self):
        """Do something when MITMf detects the config file has been modified"""
        pass

    def options(self, options):
        '''Add your options to the options parser'''
        pass

    def reactor(self, strippingFactory):
        '''This makes it possible to set up another instance of the reactor on a diffrent port, passed the default factory'''
        pass

    def setup_logger(self):
        formatter = logging.Formatter("%(asctime)s [{}] %(message)s".format(self.name), datefmt="%Y-%m-%d %H:%M:%S")
        self.log = logger().setup_logger(self.name, formatter)

        formatter = logging.Formatter("%(asctime)s %(clientip)s [type:%(browser)s-%(browserv)s os:%(clientos)s] [{}] %(message)s".format(self.name), datefmt="%Y-%m-%d %H:%M:%S")
        self.clientlog = logger().setup_logger("{}_{}".format(self.name, "clientlog"), formatter)

    def on_shutdown(self):
        '''This will be called when shutting down'''
        pass
