from scapy.all import IP, TCP, UDP, ICMP, Raw
from ..utils.display import print_packet_info


class PacketAnalyzer:

    def __init__(self, only_data: bool = False):
        self.only_data = only_data

    def analyze(self, packet):
        if IP in packet:
            payload = None
            proto = None

            if TCP in packet:
                proto = "TCP"
                if packet.haslayer(Raw):
                    try:
                        payload_bytes = packet[Raw].load
                        payload = payload_bytes.decode(errors="ignore")
                    except Exception:
                        payload = None

            elif UDP in packet:
                proto = "UDP"
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode(errors="ignore")
                    except Exception:
                        payload = None

            elif ICMP in packet:
                proto = "ICMP"

            if payload is None and self.only_data:
                return

            print_packet_info(
                src=packet[IP].src,
                dst=packet[IP].dst,
                proto=proto or "Other",
                length=len(packet),
                data=payload,
            )

        def extract_http_body(http_text: str) -> str:
            parts = http_text.split("\r\n\r\n", 1)
            if len(parts) == 2:
                headers, body = parts
                return body
