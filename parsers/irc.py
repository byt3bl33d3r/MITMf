from parsers.parser import Parser
import re

class IRC(Parser):
	name = 'IRC'

	irc_user_re = re.compile(r'NICK (.+?)((\r)?\n|\s)')
	irc_pw_re = re.compile(r'NS IDENTIFY (.+)')
	irc_pw_re2 = re.compile('nickserv :identify (.+)')

	def TCP_Parser(self, payload, src_ip_port, dst_ip_port):
	    user_search = self.irc_user_re.match(payload)
	    pass_search = self.irc_pw_re.match(payload)
	    pass_search2 = self.irc_pw_re2.search(payload.lower())

	    if user_search:
	        self.logger('IRC nick: {}'.format(user_search.group(1)))
	    if pass_search:
	        self.logger('IRC pass: {}'.format(pass_search.group(1)))
	    if pass_search2:
	        self.logger('IRC pass: {}'.format(pass_search2.group(1)))