import logging
import sys
import threading
from socket import error as socketerror
from impacket import version, smbserver, LOG
from core.configwatcher import ConfigWatcher
from core.utils import shutdown

LOG.setLevel(logging.INFO)
LOG.propagate = False
logging.getLogger('smbserver').setLevel(logging.INFO)
logging.getLogger('impacket').setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s [SMBserver] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
fileHandler = logging.FileHandler("./logs/mitmf.log")
streamHandler = logging.StreamHandler(sys.stdout)
fileHandler.setFormatter(formatter)
streamHandler.setFormatter(formatter)
LOG.addHandler(fileHandler)
LOG.addHandler(streamHandler)

class SMBserver(ConfigWatcher):

    impacket_ver = version.VER_MINOR

    def __init__(self, listenAddress = '0.0.0.0', listenPort=445, configFile=''):
        
        try:
            self.server = smbserver.SimpleSMBServer(listenAddress, listenPort, configFile)
            self.server.setSMBChallenge(self.config["MITMf"]["SMB"]["Challenge"])
        except socketerror as e:
            if "Address already in use" in e:
                shutdown("\n[-] Unable to start SMB server on port 445: port already in use")

    def start(self):
        t = threading.Thread(name='SMBserver', target=self.server.start)
        t.setDaemon(True)
        t.start()

"""
class SMBserver(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file', 'None')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        #smbConfig.add_section(DUMMY_SHARE)
        #smbConfig.set(DUMMY_SHARE,'comment','')
        #smbConfig.set(DUMMY_SHARE,'read only','no')
        #smbConfig.set(DUMMY_SHARE,'share type','0')
        #smbConfig.set(DUMMY_SHARE,'path',SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)

        self.smb.processConfigFile()
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()
"""