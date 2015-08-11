#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
import sys
import socket
import utils
import logging

from core.logger import logger
from core.configwatcher import ConfigWatcher

__version__ = 'Responder 2.2'

class Settings(ConfigWatcher):
    
    def __init__(self):
        self.ResponderPATH = os.path.dirname(__file__)
        self.Bind_To = '0.0.0.0'

    def __str__(self):
        ret = 'Settings class:\n'
        for attr in dir(self):
            value = str(getattr(self, attr)).strip()
            ret += "    Settings.%s = %s\n" % (attr, value)
        return ret

    def toBool(self, str):
        return True if str.upper() == 'ON' else False

    def ExpandIPRanges(self):
        def expand_ranges(lst):
            ret = []
            for l in lst:
                tab = l.split('.')
                x = {}
                i = 0
                for byte in tab:
                    if '-' not in byte:
                        x[i] = x[i+1] = int(byte)
                    else:
                        b = byte.split('-')
                        x[i] = int(b[0])
                        x[i+1] = int(b[1])
                    i += 2
                for a in range(x[0], x[1]+1):
                    for b in range(x[2], x[3]+1):
                        for c in range(x[4], x[5]+1):
                            for d in range(x[6], x[7]+1):
                                ret.append('%d.%d.%d.%d' % (a, b, c, d))
            return ret

        self.RespondTo = expand_ranges(self.RespondTo)
        self.DontRespondTo = expand_ranges(self.DontRespondTo)

    def populate(self, options):

        # Servers
        self.SSL_On_Off      = self.toBool(self.config['Responder']['HTTPS'])
        self.SQL_On_Off      = self.toBool(self.config['Responder']['SQL'])
        self.FTP_On_Off      = self.toBool(self.config['Responder']['FTP'])
        self.POP_On_Off      = self.toBool(self.config['Responder']['POP'])
        self.IMAP_On_Off     = self.toBool(self.config['Responder']['IMAP'])
        self.SMTP_On_Off     = self.toBool(self.config['Responder']['SMTP'])
        self.LDAP_On_Off     = self.toBool(self.config['Responder']['LDAP'])
        self.Krb_On_Off      = self.toBool(self.config['Responder']['Kerberos'])

        # Db File
        self.DatabaseFile    = './logs/responder/Responder.db'

        # Log Files
        self.LogDir = './logs/responder'

        if not os.path.exists(self.LogDir):
            os.mkdir(self.LogDir)

        self.SessionLogFile      = os.path.join(self.LogDir, 'Responder-Session.log')
        self.PoisonersLogFile    = os.path.join(self.LogDir, 'Poisoners-Session.log')
        self.AnalyzeLogFile      = os.path.join(self.LogDir, 'Analyzer-Session.log')

        self.FTPLog          = os.path.join(self.LogDir, 'FTP-Clear-Text-Password-%s.txt')
        self.IMAPLog         = os.path.join(self.LogDir, 'IMAP-Clear-Text-Password-%s.txt')
        self.POP3Log         = os.path.join(self.LogDir, 'POP3-Clear-Text-Password-%s.txt')
        self.HTTPBasicLog    = os.path.join(self.LogDir, 'HTTP-Clear-Text-Password-%s.txt')
        self.LDAPClearLog    = os.path.join(self.LogDir, 'LDAP-Clear-Text-Password-%s.txt')
        self.SMBClearLog     = os.path.join(self.LogDir, 'SMB-Clear-Text-Password-%s.txt')
        self.SMTPClearLog    = os.path.join(self.LogDir, 'SMTP-Clear-Text-Password-%s.txt')
        self.MSSQLClearLog   = os.path.join(self.LogDir, 'MSSQL-Clear-Text-Password-%s.txt')

        self.LDAPNTLMv1Log   = os.path.join(self.LogDir, 'LDAP-NTLMv1-Client-%s.txt')
        self.HTTPNTLMv1Log   = os.path.join(self.LogDir, 'HTTP-NTLMv1-Client-%s.txt')
        self.HTTPNTLMv2Log   = os.path.join(self.LogDir, 'HTTP-NTLMv2-Client-%s.txt')
        self.KerberosLog     = os.path.join(self.LogDir, 'MSKerberos-Client-%s.txt')
        self.MSSQLNTLMv1Log  = os.path.join(self.LogDir, 'MSSQL-NTLMv1-Client-%s.txt')
        self.MSSQLNTLMv2Log  = os.path.join(self.LogDir, 'MSSQL-NTLMv2-Client-%s.txt')
        self.SMBNTLMv1Log    = os.path.join(self.LogDir, 'SMB-NTLMv1-Client-%s.txt')
        self.SMBNTLMv2Log    = os.path.join(self.LogDir, 'SMB-NTLMv2-Client-%s.txt')
        self.SMBNTLMSSPv1Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv1-Client-%s.txt')
        self.SMBNTLMSSPv2Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv2-Client-%s.txt')

        # HTTP Options
        self.Serve_Exe        = self.toBool(self.config['Responder']['HTTP Server']['Serve-Exe'])
        self.Serve_Always     = self.toBool(self.config['Responder']['HTTP Server']['Serve-Always'])
        self.Serve_Html       = self.toBool(self.config['Responder']['HTTP Server']['Serve-Html'])
        self.Html_Filename    = self.config['Responder']['HTTP Server']['HtmlFilename']
        self.HtmlToInject     = self.config['Responder']['HTTP Server']['HTMLToInject']
        self.Exe_Filename     = self.config['Responder']['HTTP Server']['ExeFilename']
        self.Exe_DlName       = self.config['Responder']['HTTP Server']['ExeDownloadName']
        self.WPAD_Script      = self.config['Responder']['HTTP Server']['WPADScript']

        if not os.path.exists(self.Html_Filename):
            print "Warning: %s: file not found" % self.Html_Filename

        if not os.path.exists(self.Exe_Filename):
            print "Warning: %s: file not found" % self.Exe_Filename

        # SSL Options
        self.SSLKey  = self.config['Responder']['HTTPS Server']['SSLKey']
        self.SSLCert = self.config['Responder']['HTTPS Server']['SSLCert']

        # Respond to hosts
        self.RespondTo         = filter(None, [x.upper().strip() for x in self.config['Responder']['RespondTo'].strip().split(',')])
        self.RespondToName     = filter(None, [x.upper().strip() for x in self.config['Responder']['RespondToName'].strip().split(',')])
        self.DontRespondTo     = filter(None, [x.upper().strip() for x in self.config['Responder']['DontRespondTo'].strip().split(',')])
        self.DontRespondToName = filter(None, [x.upper().strip() for x in self.config['Responder']['DontRespondToName'].strip().split(',')])

        # CLI options
        self.Interface       = options.interface
        self.Force_WPAD_Auth = options.forcewpadauth
        self.LM_On_Off       = options.lm
        self.WPAD_On_Off     = options.wpad
        self.Wredirect       = options.wredir
        self.NBTNSDomain     = options.nbtns
        self.Basic           = options.basic
        self.Finger_On_Off   = options.finger
        self.AnalyzeMode     = options.analyze
        #self.Upstream_Proxy  = options.Upstream_Proxy

        self.Verbose = True
        if options.log_level == 'debug':
            self.Verbose = True

        self.Bind_To = utils.FindLocalIP(self.Interface)

        self.IP_aton         = socket.inet_aton(self.Bind_To)
        self.Os_version      = sys.platform

        # Set up Challenge
        self.NumChal = self.config['Responder']['Challenge']

        if len(self.NumChal) is not 16:
            print "The challenge must be exactly 16 chars long.\nExample: 1122334455667788"
            sys.exit(-1)

        self.Challenge = ""
        for i in range(0, len(self.NumChal),2):
            self.Challenge += self.NumChal[i:i+2].decode("hex")

        # Set up logging
        formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        self.ResponderLogger = logger().setup_logger("Responder", formatter, self.SessionLogFile)
        #logging.warning('Responder Started: {}'.format(self.CommandLine))
        #logging.warning('Responder Config: {}'.format(self))

        self.PoisonersLogger = logger().setup_logger("Poison log", formatter, self.PoisonersLogFile)
        self.AnalyzeLogger = logger().setup_logger("Analyze Log", formatter, self.AnalyzeLogFile)

Config = Settings()