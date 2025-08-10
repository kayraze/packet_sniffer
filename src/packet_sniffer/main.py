from .sniffing.capture import PacketSniffer

def main():
    print("[main]")
    sniffer = PacketSniffer(
        interface="wlp4s0",
        packet_count=10,
        filter_exp="tcp"
    )
    sniffer.start()

if __name__ == "__main__":
    main()