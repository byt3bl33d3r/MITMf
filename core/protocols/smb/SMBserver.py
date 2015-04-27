import logging
import threading
import sys
from impacket import smbserver, LOG

LOG.setLevel(logging.INFO)
LOG.propagate = False
#logging.getLogger('smbserver').setLevel(logging.INFO)
#logging.getLogger('impacket').setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s [SMBserver] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
fileHandler = logging.FileHandler("./logs/mitmf.log")
streamHandler = logging.StreamHandler(sys.stdout)
fileHandler.setFormatter(formatter)
streamHandler.setFormatter(formatter)
LOG.addHandler(fileHandler)
LOG.addHandler(streamHandler)

class SMBserver:

    def __init__(self, listenAddress = '0.0.0.0', listenPort=445, configFile=''):

        self.server = smbserver.SimpleSMBServer(listenAddress, listenPort, configFile)

    def start(self):
        t = threading.Thread(name='SMBserver', target=self.server.start)
        t.setDaemon(True)
        t.start()