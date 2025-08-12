from scapy.all import IP, TCP, UDP, ICMP, Raw
from ..utils.display import print_packet_info
from .flow_manager import FlowManager

class PacketAnalyzer:
    def __init__(self, only_data: bool = False, full_packet_only: bool = False):
        self.only_data = only_data
        self.full_packet_only = full_packet_only
        if full_packet_only:
            self.flow_manager = FlowManager()   

    def analyze(self, packet):
        # Step 1: try to reassemble if possible
        if self.full_packet_only:
            packet = self.flow_manager.process_packet(packet)
            if packet is None:
                return  # Still waiting for more packets in this flow

        # Step 2: get payload (prefer full reassembled version)
        if hasattr(packet, "full_payload"):
            try:
                payload = packet.full_payload.decode(errors="ignore")
            except Exception:
                payload = None
        else:
            payload = self._extract_raw_payload(packet)

        if payload is None and self.only_data:
            return

        # Step 3: detect protocol AFTER we have payload
        proto = self._detect_protocol(packet, payload)

        # Step 4: display
        print_packet_info(
            src=packet[IP].src,
            dst=packet[IP].dst,
            proto=proto or "Other",
            length=len(packet),
            data=payload,
        )


    def _extract_raw_payload(self, pkt):
        if pkt.haslayer(Raw):
            try:
                return pkt[Raw].load.decode(errors="ignore")
            except Exception:
                return None
        return None

    def _detect_protocol(self, pkt, payload):
        if TCP in pkt:
            if payload and payload.startswith(("GET", "POST", "HEAD", "OPTIONS")):
                return "HTTP"
            return "TCP"
        elif UDP in pkt:
            return "UDP"
        elif ICMP in pkt:
            return "ICMP"
        return None

    @staticmethod
    def extract_http_body(http_text: str) -> str:
        parts = http_text.split("\r\n\r\n", 1)
        return parts[1] if len(parts) == 2 else ""
