from scapy.all import IP, TCP, Raw
from .protocols import HTTPProtocol, TCPProtocol, Protocol


class Packet:
    protocols = [HTTPProtocol, TCPProtocol, Protocol]  # Order matters

    def __init__(self, scapy_pkt):
        self.pkt = scapy_pkt
        self._protocol = self.detect_protocol()

    def detect_protocol(self) -> Protocol:
        for proto_cls in self.protocols:
            if proto_cls.match(self.pkt):
                return proto_cls()  # Could pass pkt if needed
        return Protocol()

    @property
    def protocol(self) -> Protocol:
        return self._protocol

    @property
    def src_ip(self) -> str:
        return self.pkt[IP].src if self.pkt.haslayer(IP) else None

    @property
    def dst_ip(self) -> str:
        return self.pkt[IP].dst if self.pkt.haslayer(IP) else None

    def summary(self):
        return f"{self.protocol}: {self.pkt.summary()}"


class TCPacket(Packet):
    @property
    def src_port(self):
        return self.pkt[TCP].sport if self.pkt.haslayer(TCP) else None

    @property
    def dst_port(self):
        return self.pkt[TCP].dport if self.pkt.haslayer(TCP) else None

    @property
    def payload(self):
        return self.pkt[Raw].load if self.pkt.haslayer(Raw) else None


class PacketData:
    """Represents parsed application-layer data (e.g., HTTP headers & body)."""

    def __init__(self, raw_data: bytes):
        decoded = raw_data.decode("utf-8", errors="replace") if raw_data else ""
        self.raw_text = decoded
        self._split_headers_body()

    def _split_headers_body(self):
        if "\r\n\r\n" in self.raw_text:
            self.headers, self.body = self.raw_text.split("\r\n\r\n", 1)
        else:
            self.headers, self.body = self.raw_text, ""

    def has_header(self):
        return bool(self.headers.strip())

    def get_header(self):
        return self.headers

    def has_body(self):
        return bool(self.body.strip())

    def get_body(self):
        return self.body


class HTTPPacket(TCPacket):
    def has_data(self):
        return bool(self.payload)

    def get_data(self) -> PacketData:
        return PacketData(self.payload) if self.payload else None


# -------- Example usage --------
if __name__ == "__main__":
    from scapy.all import sniff

    pkt = sniff(count=1)[0]
    packet = Packet(pkt)

    if isinstance(packet.protocol, HTTPProtocol):
        http_packet = HTTPPacket(pkt)
        if http_packet.has_data():
            packet_data = http_packet.get_data()
            header = packet_data.get_header() if packet_data.has_header() else ""
            body = packet_data.get_body() if packet_data.has_body() else ""

            print(f"{http_packet.src_ip}: {header}\n\n{body}")
