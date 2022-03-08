from scapy.all import *

ARPisat = 2

indicators = []

class ArpSpoofDetectSession(DefaultSession):

    def on_packet_received(self, pkt):
        """
        for every arp packet that comes through, check the following
        - ping the host and see if there is a response
        - get ARP table and look to see duplicate entries with different IPs
        - DIDI THINK OF SOMETHING
        """
        # INDICATOR 1: Host machine of is_at pkt not responding to ping req.
        if pkt[ARP].op == ARPisat:
            ping_pkt = Ether(dst=pkt[ARP].hwsrc)/IP(dst=pkt[ARP].psrc)/ICMP()
            res = srp1(ping_pkt, timeout=1)
            if not res:
                indicators.append("host not replying to ping")
                return

        # INDICATOR 2: Arp table contains duplicate MACs for different IPs
        # INDICATOR 3: DIDI YA SHARMIT

sniff(lfilter= lambda pkt: (ARP in pkt and pkt[ARP].hwsrc != (Ether())[Ether].src),session=ArpSpoofDetectSession, stop_filter=lambda x: len(indicators) >= 2)
if len(indicators) >= 2:
    print("You are being arpspoofed. The following has happened")
    for ind in indicators:
        print(ind)

# import os
# import re
# import time

# mac_address_regex = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')


# def check_mac_address(mac_address):
#     if re.match(mac_address_regex, mac_address):
#         return True
#     else:
#         return False

# def arp_table_function():
#     arp_table = os.popen("arp -a").read()
    
#     arp_table = arp_table.split('\n')
    
#     MAC_addresses = []
#     for arpLine in arp_table:
#         if arpLine == '':
#             continue
#         arpLine = arpLine.split(" ")
#         if check_mac_address(arpLine[3]):
#             MAC_addresses.append(arpLine[3])

#     return MAC_addresses
        
# def find_a_match():
#     MAC_addresses= arp_table_function()
#     #check if there is 2 same mac address in the arp table with 2 different ip address
#     for i in MAC_addresses:
#         if MAC_addresses.count(i) > 1:
#             print("warning: there is 2 same mac address in the arp table with 2 different ip address")

# if __name__ == "__main__":
#     while True:
#         find_a_match()
#         time.sleep(15)
