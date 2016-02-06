import logging
import sys
from datetime import datetime 

class ProxyLoggerAdapter(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        return '[{}] {} [type:{}-{} os:{}] {}'.format(self.extra['proxy'], 
                                                      self.extra['client'],
                                                      self.extra['browser'],
                                                      self.extra['browser_v'],
                                                      self.extra['os'],
                                                      msg), kwargs

class DebugLoggerAdapter(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        return '[DEBUG][{}] {}'.format(self.extra['source'], msg), kwargs

class NetCredsAdapter(logging.LoggerAdapter):

    def __init__(self, logger, extra):
        self.logger = logger
        self.extra = extra
        self.extra['dst_ip_port'] = None

    def process(self, msg, kwargs):
        if self.extra['dst_ip_port'] is not None:
            return '[Net-Creds][{}][{} > {}] {}'.format(self.extra['parser'], 
                                                        self.extra['src_ip_port'],
                                                        self.extra['dst_ip_port'], 
                                                        msg), kwargs
        else:
            return '[Net-Creds][{}][{}] {}'.format(self.extra['parser'],
                                                   self.extra['src_ip_port'].split(':')[0], 
                                                   msg), kwargs

def setup_logger(level=logging.INFO):

    formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%m-%d-%Y %H:%M:%S")
    fileHandler = logging.FileHandler('./logs/MITMf_{}.log'.format(datetime.now().strftime('%Y-%m-%d')))
    fileHandler.setFormatter(formatter)

    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    mitmf_logger = logging.getLogger('MITMf')
    mitmf_logger.propagate = False
    mitmf_logger.addHandler(streamHandler)
    mitmf_logger.addHandler(fileHandler)
    mitmf_logger.setLevel(level)