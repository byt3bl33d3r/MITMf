from parsers.parser import Parser
import re

class FTP(Parser):
	name = 'FTP'

	ftp_user_re = re.compile(r'USER (.+)\r\n')
	ftp_pw_re = re.compile(r'PASS (.+)\r\n')

	def TCP_Parser(self, payload, src_ip_port, dest_ip_port):
	    # Sometimes FTP packets double up on the authentication lines
	    # We just want the lastest one. Ex: "USER danmcinerney\r\nUSER danmcinerney\r\n"
	    num = payload.lower().count('USER')
	    if num > 1:
	        lines = payload.count('\r\n')
	        if lines > 1:
	            payload = payload.split('\r\n')[-2] # -1 is ''

	    # FTP and POP potentially use idential client > server auth pkts
	    ftp_user = self.ftp_user_re.match(payload)
	    ftp_pass = self.ftp_pass_re.match(payload)

	    if ftp_user:
	        self.logger('FTP User: {}'.format(ftp_user.group(1).strip()))
	        if dst_ip_port[-3:] != ':21':
	            self.logger('Nonstandard FTP port, confirm the service that is running on it')

	    elif ftp_pass:
	        self.logger('FTP Pass: {}'.format(ftp_pass.group(1).strip()))
	        if dst_ip_port[-3:] != ':21':
	            self.logger('Nonstandard FTP port, confirm the service that is running on it')