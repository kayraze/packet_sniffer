from scapy.all import IP, TCP, UDP, ICMP
from ..utils.display import print_packet_info

class PacketAnalyzer:
    def analyze(self, packet):
        if IP in packet:
            proto = None
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"
            elif ICMP in packet:
                proto = "ICMP"

            print_packet_info(
                src=packet[IP].src,
                dst=packet[IP].dst,
                proto=proto or "Other",
                length=len(packet)
            )