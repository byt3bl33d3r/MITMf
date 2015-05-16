#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

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
import random
import logging
import re
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr, get_if_hwaddr
from core.sergioproxy.ProxyPlugins import ProxyPlugins

mitmf_logger = logging.getLogger('mitmf')

def shutdown(message=None):
    for plugin in ProxyPlugins.getInstance().plist:
        plugin.finish()
    sys.exit(message)

class SystemConfig:

    @staticmethod
    def setIpForwarding(value):
        mitmf_logger.debug("[Utils] Setting ip forwarding to {}".format(value))
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
            file.write(str(value))
            file.close()
    
    @staticmethod
    def getIP(interface):
        try:
            ip_address = get_if_addr(interface)
            if (ip_address == "0.0.0.0") or (ip_address is None):
                shutdown("[Utils] Interface {} does not have an assigned IP address".format(interface))

            return ip_address
        except Exception, e:
            shutdown("[Utils] Error retrieving IP address from {}: {}".format(interface, e))
    
    @staticmethod
    def getMAC(interface):
        try:
            mac_address = get_if_hwaddr(interface)
            return mac_address
        except Exception, e:
            shutdown("[Utils] Error retrieving MAC address from {}: {}".format(interface, e))

class IpTables:

    _instance = None

    def __init__(self):
        self.dns   = False
        self.http  = False

    @staticmethod
    def getInstance():
        if IpTables._instance == None:
            IpTables._instance = IpTables()

        return IpTables._instance

    def Flush(self):
        mitmf_logger.debug("[Utils] Flushing iptables")
        os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
        self.dns  = False
        self.http = False

    def HTTP(self, http_redir_port):
        mitmf_logger.debug("[Utils] Setting iptables HTTP redirection rule from port 80 to {}".format(http_redir_port))
        os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port {}'.format(http_redir_port))
        self.http = True

    def DNS(self, ip, port):
        mitmf_logger.debug("[Utils] Setting iptables DNS redirection rule from port 53 to {}:{}".format(ip, port))
        os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to {}:{}'.format(ip, port))
        self.dns = True

class Banners:

    banner1 = """                                                    
 __  __   ___   .--.          __  __   ___              
|  |/  `.'   `. |__|         |  |/  `.'   `.      _.._  
|   .-.  .-.   '.--.     .|  |   .-.  .-.   '   .' .._| 
|  |  |  |  |  ||  |   .' |_ |  |  |  |  |  |   | '     
|  |  |  |  |  ||  | .'     ||  |  |  |  |  | __| |__   
|  |  |  |  |  ||  |'--.  .-'|  |  |  |  |  ||__   __|  
|  |  |  |  |  ||  |   |  |  |  |  |  |  |  |   | |     
|__|  |__|  |__||__|   |  |  |__|  |__|  |__|   | |     
                       |  '.'                   | |     
                       |   /                    | |     
                       `'-'                     |_|
"""

    banner2= """
 ███▄ ▄███▓ ██▓▄▄▄█████▓ ███▄ ▄███▓  █████▒
▓██▒▀█▀ ██▒▓██▒▓  ██▒ ▓▒▓██▒▀█▀ ██▒▓██   ▒ 
▓██    ▓██░▒██▒▒ ▓██░ ▒░▓██    ▓██░▒████ ░ 
▒██    ▒██ ░██░░ ▓██▓ ░ ▒██    ▒██ ░▓█▒  ░ 
▒██▒   ░██▒░██░  ▒██▒ ░ ▒██▒   ░██▒░▒█░    
░ ▒░   ░  ░░▓    ▒ ░░   ░ ▒░   ░  ░ ▒ ░    
░  ░      ░ ▒ ░    ░    ░  ░      ░ ░      
░      ░    ▒ ░  ░      ░      ░    ░ ░    
       ░    ░                  ░                                                     
"""

    banner3 = """
   ▄▄▄▄███▄▄▄▄    ▄█      ███       ▄▄▄▄███▄▄▄▄      ▄████████ 
 ▄██▀▀▀███▀▀▀██▄ ███  ▀█████████▄ ▄██▀▀▀███▀▀▀██▄   ███    ███ 
 ███   ███   ███ ███▌    ▀███▀▀██ ███   ███   ███   ███    █▀  
 ███   ███   ███ ███▌     ███   ▀ ███   ███   ███  ▄███▄▄▄     
 ███   ███   ███ ███▌     ███     ███   ███   ███ ▀▀███▀▀▀     
 ███   ███   ███ ███      ███     ███   ███   ███   ███        
 ███   ███   ███ ███      ███     ███   ███   ███   ███        
  ▀█   ███   █▀  █▀      ▄████▀    ▀█   ███   █▀    ███        
"""

    banner4 = """
      ___                                     ___           ___     
     /\  \                                   /\  \         /\__\    
    |::\  \       ___           ___         |::\  \       /:/ _/_   
    |:|:\  \     /\__\         /\__\        |:|:\  \     /:/ /\__\  
  __|:|\:\  \   /:/__/        /:/  /      __|:|\:\  \   /:/ /:/  /  
 /::::|_\:\__\ /::\  \       /:/__/      /::::|_\:\__\ /:/_/:/  /   
 \:\~~\  \/__/ \/\:\  \__   /::\  \      \:\~~\  \/__/ \:\/:/  /    
  \:\  \        ~~\:\/\__\ /:/\:\  \      \:\  \        \::/__/     
   \:\  \          \::/  / \/__\:\  \      \:\  \        \:\  \     
    \:\__\         /:/  /       \:\__\      \:\__\        \:\__\    
     \/__/         \/__/         \/__/       \/__/         \/__/    
"""
    
    banner5 = """
███╗   ███╗██╗████████╗███╗   ███╗███████╗
████╗ ████║██║╚══██╔══╝████╗ ████║██╔════╝
██╔████╔██║██║   ██║   ██╔████╔██║█████╗  
██║╚██╔╝██║██║   ██║   ██║╚██╔╝██║██╔══╝  
██║ ╚═╝ ██║██║   ██║   ██║ ╚═╝ ██║██║     
╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝     
"""
    
    def printBanner(self):
        banners = [self.banner1, self.banner2, self.banner3, self.banner4, self.banner5]
        print random.choice(banners)