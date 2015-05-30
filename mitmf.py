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

import argparse
import sys
import os
import logging
import threading

from twisted.web import http
from twisted.internet import reactor
from core.sslstrip.CookieCleaner import CookieCleaner
from core.sergioproxy.ProxyPlugins import ProxyPlugins
from core.utils import Banners, SystemConfig, shutdown
from plugins import *

Banners().printBanner()

if os.geteuid() != 0:
    sys.exit("[-] When man-in-the-middle you want, run as r00t you will, hmm?")

mitmf_version = "0.9.7"
sslstrip_version = "0.9"
sergio_version = "0.2.1"

parser = argparse.ArgumentParser(description="MITMf v{} - Framework for MITM attacks".format(mitmf_version), version=mitmf_version, usage='mitmf.py -i interface [mitmf options] [plugin name] [plugin options]', epilog="Use wisely, young Padawan.",fromfile_prefix_chars='@')

#add MITMf options
mgroup = parser.add_argument_group("MITMf", "Options for MITMf")
mgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level [default: info]")
mgroup.add_argument("-i", "--interface", required=True, type=str,  metavar="interface" ,help="Interface to listen on")
mgroup.add_argument("-c", "--config-file", dest='configfile', type=str, default="./config/mitmf.conf", metavar='configfile', help="Specify config file to use")
mgroup.add_argument('-m', '--manual-iptables', dest='manualiptables', action='store_true', default=False, help='Do not setup iptables or flush them automatically')

#add sslstrip options
sgroup = parser.add_argument_group("SSLstrip", "Options for SSLstrip library")
slogopts = sgroup.add_mutually_exclusive_group()
slogopts.add_argument("-p", "--post", action="store_true",help="Log only SSL POSTs. (default)")
slogopts.add_argument("-s", "--ssl", action="store_true", help="Log all SSL traffic to and from server.")
slogopts.add_argument("-a", "--all", action="store_true", help="Log all SSL and HTTP traffic to and from server.")
sgroup.add_argument("-l", "--listen", type=int, metavar="port", default=10000, help="Port to listen on (default 10000)")
sgroup.add_argument("-f", "--favicon", action="store_true", help="Substitute a lock favicon on secure requests.")
sgroup.add_argument("-k", "--killsessions", action="store_true", help="Kill sessions in progress.")

#Initialize plugins
plugin_classes = plugin.Plugin.__subclasses__()

plugins = []
try:
    for p in plugin_classes:
        plugins.append(p())
except Exception as e:
    print "[-] Failed to load plugin class {}: {}".format(p, e)


arg_dict = dict() #dict containing a plugin's optname with it's relative options

#Give subgroup to each plugin with options
try:
    for p in plugins:
        if p.desc == "":
            sgroup = parser.add_argument_group(p.name,"Options for {}.".format(p.name))
        else:
            sgroup = parser.add_argument_group(p.name, p.desc)

        sgroup.add_argument("--{}".format(p.optname), action="store_true",help="Load plugin {}".format(p.name))

        if p.has_opts:
            p.pluginOptions(sgroup)

        arg_dict[p.optname] = vars(sgroup)['_group_actions']

except NotImplementedError:
    sys.exit("[-] {} plugin claimed option support, but didn't have it.".format(p.name))

if len(sys.argv) is 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

# Definitely a better way to do this, will need to clean this up in the future
# Checks to see if we called a plugin's options without first invoking the actual plugin
for plugin, options in arg_dict.iteritems():
    if vars(args)[plugin] is False:
        for option in options:
            if vars(args)[option.dest]:
                sys.exit("[-] Called plugin options without invoking the actual plugin (--{})".format(plugin))

#check to see if we supplied a valid interface
myip  = SystemConfig.getIP(args.interface)
mymac = SystemConfig.getMAC(args.interface)

#Start logging
log_level = logging.__dict__[args.log_level.upper()]

logging.basicConfig(level=log_level, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logFormatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
mitmf_logger = logging.getLogger('mitmf')
fileHandler = logging.FileHandler("./logs/mitmf.log")
fileHandler.setFormatter(logFormatter)
mitmf_logger.addHandler(fileHandler)

#####################################################################################################

#All our options should be loaded now, initialize the plugins
print "[*] MITMf v{} online... initializing plugins".format(mitmf_version)

for p in plugins:

    #load only the plugins that have been called at the command line
    if vars(args)[p.optname] is True:

        print "|_ {} v{}".format(p.name, p.version)
        if p.tree_info:
            for line in xrange(0, len(p.tree_info)):
                print "|  |_ {}".format(p.tree_info.pop())

        p.initialize(args)

        if p.tree_info:
            for line in xrange(0, len(p.tree_info)):
                print "|  |_ {}".format(p.tree_info.pop())

        ProxyPlugins.getInstance().addPlugin(p)

#Plugins are ready to go, let's rock & roll
from core.sslstrip.StrippingProxy import StrippingProxy
from core.sslstrip.URLMonitor import URLMonitor

URLMonitor.getInstance().setFaviconSpoofing(args.favicon)
CookieCleaner.getInstance().setEnabled(args.killsessions)

strippingFactory          = http.HTTPFactory(timeout=10)
strippingFactory.protocol = StrippingProxy

reactor.listenTCP(args.listen, strippingFactory)

for p in ProxyPlugins.getInstance().plist:

    p.pluginReactor(strippingFactory) #we pass the default strippingFactory, so the plugins can use it
    p.startConfigWatch()

    t = threading.Thread(name='{}-thread'.format(p.name), target=p.startThread, args=(args,))
    t.setDaemon(True)
    t.start()

print "|"
print "|_ Sergio-Proxy v{} online".format(sergio_version)
print "|_ SSLstrip v{} by Moxie Marlinspike online".format(sslstrip_version)

#Start Net-Creds
from core.netcreds.NetCreds import NetCreds
NetCreds().start(args.interface, myip)
print "|_ Net-Creds v{} online".format(NetCreds.version)

#Start DNSChef
from core.servers.dns.DNSchef import DNSChef
DNSChef.getInstance().start()
print "|_ DNSChef v{} online".format(DNSChef.version)

#Start the HTTP Server
from core.servers.http.HTTPServer import HTTPServer
HTTPServer.getInstance().start()
print "|_ HTTP server online"

#Start the SMB server
from core.servers.smb.SMBserver import SMBserver
print "|_ SMB server online [Mode: {}] (Impacket {}) \n".format(SMBserver.getInstance().server_type, SMBserver.getInstance().impacket_ver)
SMBserver.getInstance().start()

#start the reactor
reactor.run()

print "\n"
shutdown()