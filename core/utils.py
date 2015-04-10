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

class SystemConfig:

	@staticmethod
	def setIpForwarding(value):
		with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
			file.write(str(value))
			file.close()

	class iptables:

		@staticmethod
		def Flush():
			os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')

		@staticmethod
		def HTTP(http_redir_port):
			os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port %s' % http_redir_port)

		@staticmethod
		def DNS(queue_number):
			os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num %s' % queue_number)

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

	def printBanner(self):
		banners = [self.banner1, self.banner2, self.banner3, self.banner4]
		print random.choice(banners)