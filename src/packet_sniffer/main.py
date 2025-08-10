from .sniffing.capture import PacketSniffer
import argparse

def main():
    print("[main]")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        'filter', 
        nargs="?",
        default="",
        help="BPF filter expression for capturing (e.g., 'tcp', 'udp', 'port 80')"
    )
    parser.add_argument(
        'interface',
        nargs="?",
        default=None,
        help='The interface to listen on (positional)'
    )
    

    parser.add_argument(
        "-i", "--interface",
        dest="interface_flag",
        help="The interface to listen on (flag version)"
    )

    parser.add_argument(
        '-pc', '--packet-count', 
        type=int,
        default=0,
        help='How many packets to capture before stopping'
        )
    args = parser.parse_args()

    interface = args.interface_flag or args.interface
    
    sniffer = PacketSniffer(
        interface=interface,
        packet_count=args.packet_count,
        filter_exp=args.filter
    )
    sniffer.start()

if __name__ == "__main__":


    main()