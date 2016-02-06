from parsers.parser import Parser
from collections import OrderedDict

class Telnet(Parser):
    name = 'Telnet'

    telnet_stream = OrderedDict()

    def TCP_parser(self, payload, src_ip_port, dst_ip_port):
        if src_ip_port in self.telnet_stream:
            # Do a utf decode in case the client sends telnet options before their username
            # No one would care to see that
            try:
                self.telnet_stream[src_ip_port] += payload.decode('utf8')
            except UnicodeDecodeError:
                pass

            # \r or \r\n or \n terminate commands in telnet if my pcaps are to be believed
            if '\r' in self.telnet_stream[src_ip_port] or '\n' in self.telnet_stream[src_ip_port]:
                telnet_split = self.telnet_stream[src_ip_port].split(' ', 1)
                cred_type = telnet_split[0]
                value = telnet_split[1].replace('\r\n', '').replace('\r', '').replace('\n', '')
                # Create msg, the return variable
                self.logger('Telnet %s: %s' % (cred_type, value))
                del self.telnet_stream[src_ip_port]

        # This part relies on the telnet packet ending in
        # "login:", "password:", or "username:" and being <750 chars
        # Haven't seen any false+ but this is pretty general
        # might catch some eventually
        # maybe use dissector.py telnet lib?
        if len(self.telnet_stream) > 100:
            self.telnet_stream.popitem(last=False)
        mod_load = payload.lower().strip()
        if mod_load.endswith('username:') or mod_load.endswith('login:'):
            self.telnet_stream[dst_ip_port] = 'username '
        elif mod_load.endswith('password:'):
            self.telnet_stream[dst_ip_port] = 'password '