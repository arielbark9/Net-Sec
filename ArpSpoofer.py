from scapy.all import *
import argparse

ARP_ISAT_CODE = 2

def spoof(args : dict):
    """
    param args -> arguments supported: interface (assuming valid),source,delay,gw,target(required)
    """
    # TO DO: get target MAC
    # TO DO: send Arp packets
    arp_isat_packet = Ether()/ARP(op=ARP_ISAT_CODE,pdst=args[target])
    if args["src"] is not None:
        arp_isat_packet[Ether].src = args["src"]
    print(arp_isat_packet.show())
    


def main():
    parser = argparse.ArgumentParser(description="Spoof ARP tables")
    parser.add_argument("-i","--iface", help="Interface you wish to use", choices=get_if_list())
    parser.add_argument("-s","--src", help="The address you want for the attacker")
    parser.add_argument("-d","--delay", type=int, help="Delay (in seconds) between messages")
    parser.add_argument("-gw", action='store_true', help="should GW be attacked as well")
    parser.add_argument("-t","--target", help="IP of target", required=True)

    args = parser.parse_args()
    spoof(vars(args))


if __name__ == "__main__":
    main()