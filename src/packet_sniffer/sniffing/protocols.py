from scapy.all import TCP, Raw


class Protocol:
    name = "GENERIC"

    @classmethod
    def match(cls, pkt) -> bool:
        """Return True if packet matches this protocol."""
        return False

    def __str__(self):
        return self.name


class TCPProtocol(Protocol):
    name = "TCP"

    @classmethod
    def match(cls, pkt) -> bool:
        return pkt.haslayer(TCP)


class HTTPProtocol(TCPProtocol):
    name = "HTTP"

    @classmethod
    def match(cls, pkt) -> bool:
        if not super().match(pkt):
            return False

        if pkt.haslayer(Raw):
            payload: str = pkt[Raw].load
            return payload.startswith(
                (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"HTTP/")
            )

        return False
