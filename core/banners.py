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
import random

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
███╗   ███╗██╗████████╗███╗   ███╗███████╗
████╗ ████║██║╚══██╔══╝████╗ ████║██╔════╝
██╔████╔██║██║   ██║   ██╔████╔██║█████╗  
██║╚██╔╝██║██║   ██║   ██║╚██╔╝██║██╔══╝  
██║ ╚═╝ ██║██║   ██║   ██║ ╚═╝ ██║██║     
╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝     
"""

banner5 = """
@@@@@@@@@@   @@@  @@@@@@@  @@@@@@@@@@   @@@@@@@@  
@@@@@@@@@@@  @@@  @@@@@@@  @@@@@@@@@@@  @@@@@@@@  
@@! @@! @@!  @@!    @@!    @@! @@! @@!  @@!       
!@! !@! !@!  !@!    !@!    !@! !@! !@!  !@!       
@!! !!@ @!@  !!@    @!!    @!! !!@ @!@  @!!!:!    
!@!   ! !@!  !!!    !!!    !@!   ! !@!  !!!!!:    
!!:     !!:  !!:    !!:    !!:     !!:  !!:       
:!:     :!:  :!:    :!:    :!:     :!:  :!:       
:::     ::    ::     ::    :::     ::    ::       
 :      :    :       :      :      :     :        
"""

def get_banner():
    banners = [banner1, banner2, banner3, banner4, banner5]
    return random.choice(banners)
