import logging
import sys
import threading
import os

from socket import error as socketerror
from mitmflib.impacket import version, smbserver, LOG
from core.servers.smb.KarmaSMB import KarmaSMBServer
from core.configwatcher import ConfigWatcher
from core.utils import shutdown

class SMBserver(ConfigWatcher):

    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

        self.version   = version.VER_MINOR
        self.mode      = self.config["MITMf"]["SMB"]["mode"].lower()
        self.challenge = self.config["MITMf"]["SMB"]["Challenge"]
        self.port      = int(self.config["MITMf"]["SMB"]["port"])

    def server(self):
        try:
            if self.mode == 'normal':

                formatter = logging.Formatter("%(asctime)s [SMB] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
                self.conf_impacket_logger(formatter)

                server = smbserver.SimpleSMBServer(listenPort=self.port)
                
                for share in self.config["MITMf"]["SMB"]["Shares"]:
                    path = self.config["MITMf"]["SMB"]["Shares"][share]['path']
                    readonly = self.config["MITMf"]["SMB"]["Shares"][share]['readonly'].lower()
                    server.addShare(share.upper(), path, readOnly=readonly)

                server.setSMBChallenge(self.challenge)
                server.setLogFile('')

            elif self.mode == 'karma':

                formatter = logging.Formatter("%(asctime)s [KarmaSMB] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
                self.conf_impacket_logger(formatter)

                server = KarmaSMBServer(self.challenge, self.port)
                server.defaultFile = self.config["MITMf"]["SMB"]["Karma"]["defaultfile"]
                
                for extension, path in self.config["MITMf"]["SMB"]["Karma"].iteritems():
                    server.extensions[extension.upper()] = os.path.normpath(path)

            else:
                shutdown("\n[-] Invalid SMB server type specified in config file!")

            return server
   
        except socketerror as e:
            if "Address already in use" in e:
                shutdown("\n[-] Unable to start SMB server on port {}: port already in use".format(self.port))

    def conf_impacket_logger(self, formatter):

        LOG.setLevel(logging.INFO)
        LOG.propagate = False

        fileHandler = logging.FileHandler("./logs/mitmf.log")
        streamHandler = logging.StreamHandler(sys.stdout)
        fileHandler.setFormatter(formatter)
        streamHandler.setFormatter(formatter)
        LOG.addHandler(fileHandler)
        LOG.addHandler(streamHandler)

    def start(self):
        t = threading.Thread(name='SMBserver', target=self.server().start)
        t.setDaemon(True)
        t.start()
