from parsers.parser import Parser

class SNMP(Parser):
	name = 'SNMP'

	def UDP_Parser(self, pkt, src_ip_port, dst_ip_port):
		if pkt.haslayer(SNMP):
			if type(pkt[SNMP].community.val) == str:
				ver = pkt[SNMP].version.val
				self.logger('SNMPv{} community string: {}'.format(ver, snmp_layer.community.val))