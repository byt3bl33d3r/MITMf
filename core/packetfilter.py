from core.utils import set_ip_forwarding, iptables
from core.logger import logger
from scapy.all import *
from traceback import print_exc
from netfilterqueue import NetfilterQueue

formatter = logging.Formatter("%(asctime)s [PacketFilter] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger("PacketFilter", formatter)

class PacketFilter:

    def __init__(self, filter):
        self.filter = filter

    def start(self):
        set_ip_forwarding(1)
        iptables().NFQUEUE()

        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(0, self.modify)

        self.nfqueue.run()

    def modify(self, pkt):
        #log.debug("Got packet")
        data = pkt.get_payload()
        packet = IP(data)

        try:
            execfile(self.filter)
        except Exception:
            log.debug("Error occurred in filter")
            print_exc()

        pkt.set_payload(str(packet)) #set the packet content to our modified version
        pkt.accept() #accept the packet

    def stop(self):
        self.nfqueue.unbind()
        set_ip_forwarding(0)
        iptables().flush()