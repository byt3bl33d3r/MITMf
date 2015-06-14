#! /usr/bin/env python2.7

import logging
from mitmflib.watchdog.observers import Observer
from mitmflib.watchdog.events import FileSystemEventHandler
from configobj import ConfigObj

logging.getLogger("watchdog").setLevel(logging.ERROR) #Disables watchdog's debug messages

mitmf_logger = logging.getLogger('mitmf')

class ConfigWatcher(FileSystemEventHandler):

    _instance = None
    config = ConfigObj("./config/mitmf.conf")

    @staticmethod
    def getInstance():
        if ConfigWatcher._instance is None:
            ConfigWatcher._instance = ConfigWatcher()

        return ConfigWatcher._instance

    def startConfigWatch(self):
        observer = Observer()
        observer.schedule(self, path='./config', recursive=False)
        observer.start()

    def getConfig(self):
        return self.config

    def on_modified(self, event):
        mitmf_logger.debug("[{}] Detected configuration changes, reloading!".format(self.__class__.__name__))
        self.reloadConfig()
        self.onConfigChange()

    def onConfigChange(self):
        """ We can subclass this function to do stuff after the config file has been modified"""
        pass

    def reloadConfig(self):
        try:
            self.config = ConfigObj("./config/mitmf.conf")
        except Exception as e:
            mitmf_logger.error("Error reloading config file: {}".format(e))
            pass
