from .sniffing.capture import PacketSniffer
from scapy.all import rdpcap
import argparse
import os
from .sniffing.analyzer import PacketAnalyzer


def main():
    print("[main]")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filter",
        nargs="?",
        default="",
        help="BPF filter expression for capturing (e.g., 'tcp', 'udp', 'port 80')",
    )
    parser.add_argument(
        "interface",
        nargs="?",
        default=None,
        help="The interface to listen on (positional)",
    )

    parser.add_argument(
        "-i",
        "--interface",
        dest="interface_flag",
        help="The interface to listen on (flag version)",
    )

    parser.add_argument(
        "-pc",
        "--packet-count",
        type=int,
        default=0,
        help="How many packets to capture before stopping",
    )
    parser.add_argument(
        "--only-data", action="store_true", help="Show packets with data only"
    )
    parser.add_argument(
        "-f", "--file", help="Path to pcap or pcapng file for offline analysis"
    )
    parser.add_argument(
        "--full-packet",
        action="store_true",
        help="Combine fragmented packet data into one packet"
    )
    args = parser.parse_args()

    interface = args.interface_flag or args.interface

    packet_analyzer = PacketAnalyzer(
        only_data=args.only_data,
        full_packet_only=args.full_packet
    )

    if args.file:
        if not os.path.exists(args.file):
            parser.error(f"File not found: {args.file}")

        print(f"[+] Reading packets from {args.file}")
        packets = rdpcap(args.file)
        for packet in packets:
            packet_analyzer.analyze(packet)
    else:
        sniffer = PacketSniffer(
            analyzer=packet_analyzer,
            interface=interface,
            packet_count=args.packet_count,
            filter_exp=args.filter,
        )
        sniffer.start()


if __name__ == "__main__":

    main()
