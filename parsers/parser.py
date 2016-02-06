class Parser(object):
    name = 'Parser Name'

    def __init__(self, logger):
        self.logger = logger
        self.logger.extra['parser'] = self.name

    def TCP_Parser(self, payload, src_ip_port, dst_ip_port):
        '''
            This function is called on every TCP packet
        '''
        pass

    def UDP_Parser(self, payload, src_ip_port, dst_ip_port):
        '''
            This function is called on every UDP packet
        '''
        pass