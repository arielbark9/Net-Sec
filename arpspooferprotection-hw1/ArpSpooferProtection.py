from urllib import response
from numpy import broadcast
from scapy.all import *
import re


mac_address_regex = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
broadcast_mac_address = 'ff:ff:ff:ff:ff:ff'
ARPisat = 2

indicators = []

class ArpSpoofDetectSession(DefaultSession):
    def on_packet_received(self, pkt):
        """
        for every arp packet that comes through, check the following
        - ping the host and see if there is a response
        """
        # INDICATOR 1: Host machine of is_at pkt not responding to ping req.
        if pkt[ARP].op == ARPisat:
            ping_pkt = Ether(dst=pkt[ARP].hwsrc)/IP(dst=pkt[ARP].psrc)/ICMP()
            res = srp1(ping_pkt, timeout=1)
            if not res:
                indicators.append("host not replying to ping")
                return

    # INDICATOR 2: Arp table contains duplicate MACs for different IPs
    def arp_table_function():
        """
        - get ARP table and look to see duplicate entries with different IPs
        """
        arp_table = open("/proc/net/arp", "r").read()
        arp_table = arp_table.split('\n')
        MAC_addresses = []
        for arpLine in arp_table:
            if arpLine == '':
                continue
            arpLine = arpLine.split(" ")
            if re.match(mac_address_regex,arpLine[25]):
                MAC_addresses.append(arpLine[25])
            for i in MAC_addresses:
                if MAC_addresses.count(i) > 1:
                    indicators.append("warning: there is 2 same mac address in the arp table with 2 different ip address")
                    return     

    def duplicatesAnswars(self, pkt):
        """
        - check if there is a duplicate answer
        """
        if pkt[ARP].op == ARPisat:
            #send arp who is request to the pkt and if there is 2 answers, it is a duplicate answer
            arp_who_is = Ether(dst=broadcast_mac_address)/ARP(ARP.who_has,pdst=pkt[ARP].pscr)
            response = List(sr(arp_who_is, timeout=2))
            if len(response) > 1:
                for i in (len(response)-1):
                    if response[i][1][ARP].hwsrc != response[i+1][1][ARP].hwsrc:
                        indicators.append("warning: there is a duplicate answer")
                        return

    
    # INDICATOR 3: DIDI YA SHARMIT

sniff(lfilter= lambda pkt: (ARP in pkt and pkt[ARP].hwsrc != (Ether())[Ether].src),session=ArpSpoofDetectSession, stop_filter=lambda x: len(indicators) >= 2)
if len(indicators) >= 2:
    print("You are being arpspoofed. The following has happened")
    for ind in indicators:
        print(ind)



    
        
