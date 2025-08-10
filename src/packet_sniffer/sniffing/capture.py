from scapy.all import sniff
from .analyzer import PacketAnalyzer
from ..config import DEFAULT_INTERFACE, DEFAULT_PACKET_COUNT, DEFAULT_FILTER


class PacketSniffer:
    def __init__(
            self, 
            interface=DEFAULT_INTERFACE,
            packet_count=DEFAULT_PACKET_COUNT,
            filter_exp=DEFAULT_FILTER,
        ):
        self.interface = interface
        self.packet_count = packet_count
        self.filter_exp = filter_exp
        self.analyzer = PacketAnalyzer()

    def start(self):
        sniff(
            iface=self.interface,
            prn=self.analyzer.analyze,
            count=self.packet_count,
            filter=self.filter_exp,
            store=False
        )
        
