#!/usr/bin/env python2
import logging
import threading
from core.logger import NetCredsAdapter, DebugLoggerAdapter
from collections import OrderedDict

# stfu scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0

pkt_frag_loads = OrderedDict()
challenge_acks = OrderedDict()

netcreds_logger = NetCredsAdapter(logging.getLogger('MITMf'), {})
debug_logger = DebugLoggerAdapter(logging.getLogger('MITMf'), {'source': 'Net-Creds'})

from parsers import *
#Get everything that inherits from the Parser class
parsers = [parser(netcreds_logger) for parser in parser.Parser.__subclasses__()]
debug_logger.debug('Loaded {} parser(s)'.format(len(parsers)))

class NetCreds:

    def frag_remover(self, ack, load):
        '''
        Keep the FILO OrderedDict of frag loads from getting too large
        3 points of limit:
            Number of ip_ports < 50
            Number of acks per ip:port < 25
            Number of chars in load < 5000
        '''

        # Keep the number of IP:port mappings below 50
        # last=False pops the oldest item rather than the latest
        while len(pkt_frag_loads) > 50:
            pkt_frag_loads.popitem(last=False)

        # Loop through a deep copy dict but modify the original dict
        copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
        for ip_port in copy_pkt_frag_loads:
            if len(copy_pkt_frag_loads[ip_port]) > 0:
                # Keep 25 ack:load's per ip:port
                while len(copy_pkt_frag_loads[ip_port]) > 25:
                    pkt_frag_loads[ip_port].popitem(last=False)

        # Recopy the new dict to prevent KeyErrors for modifying dict in loop
        copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
        for ip_port in copy_pkt_frag_loads:
            # Keep the load less than 75,000 chars
            for ack in copy_pkt_frag_loads[ip_port]:
                # If load > 5000 chars, just keep the last 200 chars
                if len(copy_pkt_frag_loads[ip_port][ack]) > 5000:
                    pkt_frag_loads[ip_port][ack] = pkt_frag_loads[ip_port][ack][-200:]

    def frag_joiner(self, ack, src_ip_port, load):
        '''
        Keep a store of previous fragments in an OrderedDict named pkt_frag_loads
        '''
        for ip_port in pkt_frag_loads:
            if src_ip_port == ip_port:
                if ack in pkt_frag_loads[src_ip_port]:
                    # Make pkt_frag_loads[src_ip_port][ack] = full load
                    old_load = pkt_frag_loads[src_ip_port][ack]
                    concat_load = old_load + load
                    return OrderedDict([(ack, concat_load)])

        return OrderedDict([(ack, load)])

    def pkt_parser(self, pkt):
        '''
        Start parsing packets here
        '''
        if pkt.haslayer(Raw):
            load = pkt[Raw].load

        # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
        if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            return

        # UDP
        if pkt.haslayer(UDP) and pkt.haslayer(IP) and pkt.haslayer(Raw):

            src_ip_port = str(pkt[IP].src) + ':' + str(pkt[UDP].sport)
            dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[UDP].dport)
            for parser in parsers:
                parser.logger.extra['src_ip_port'] = src_ip_port
                parser.logger.extra['dst_ip_port'] = dst_ip_port
                parser_hook = getattr(parser, 'UDP_Parser')
                parser_hook(pkt, src_ip_port, dst_ip_port)

        # TCP
        elif pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):

            ack = str(pkt[TCP].ack)
            seq = str(pkt[TCP].seq)
            src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
            dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)
            self.frag_remover(ack, load) 
            pkt_frag_loads[src_ip_port] = self.frag_joiner(ack, src_ip_port, load)
            full_load = pkt_frag_loads[src_ip_port][ack] 
            for parser in parsers:
                parser.logger.extra['src_ip_port'] = src_ip_port
                parser.logger.extra['dst_ip_port'] = dst_ip_port
                parser_hook = getattr(parser, 'TCP_Parser')
                parser_hook(full_load, src_ip_port, dst_ip_port) #PHRASING!

    def start_sniffer(self, options, ip):
        sniff(iface=options.interface, prn=self.pkt_parser, filter="not host {}".format(ip), store=0)

    def start(self, options, ip):
        t = threading.Thread(name='Net-Creds', target=self.start_sniffer, args=(options, ip))
        t.setDaemon(True)
        t.start()