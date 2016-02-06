from parsers.parser import Parser
from collections import OrderedDict
import re

class NTLM(Parser):
	name = 'NTLM'

	NTLMSSP2_re = re.compile('NTLMSSP\x00\x02\x00\x00\x00.+')
	NTLMSSP3_re = re.compile('NTLMSSP\x00\x03\x00\x00\x00.+')
	
	def TCP_Parser(self, payload, src_ip_port, dst_ip_port):
	    # Non-NETNTLM NTLM hashes (MSSQL, DCE-RPC,SMBv1/2,LDAP, MSSQL)
	    NTLMSSP2 = re.search(NTLMSSP2_re, full_load, re.DOTALL)
	    NTLMSSP3 = re.search(NTLMSSP3_re, full_load, re.DOTALL)
	    if NTLMSSP2:
	        parse_ntlm_chal(NTLMSSP2.group(), ack)
	    if NTLMSSP3:
	        ntlm_resp_found = parse_ntlm_resp(NTLMSSP3.group(), seq)
	        if ntlm_resp_found != None:
	            printer(src_ip_port, dst_ip_port, ntlm_resp_found)

	    # Look for authentication headers
	    if len(headers) == 0:
	        authenticate_header = None
	        authorization_header = None
	    for header in headers:
	        authenticate_header = re.match(authenticate_re, header)
	        authorization_header = re.match(authorization_re, header)
	        if authenticate_header or authorization_header:
	            break

	    if authorization_header or authenticate_header:
	        # NETNTLM
	        netntlm_found = parse_netntlm(authenticate_header, authorization_header, headers, ack, seq)