import os
import re
import time

mac_address_regex = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')


def check_mac_address(mac_address):
    if re.match(mac_address_regex, mac_address):
        return True
    else:
        return False

def arp_table_function():
    arp_table = os.popen("arp -a").read()
    
    arp_table = arp_table.split('\n')
    
    MAC_addresses = []
    for arpLine in arp_table:
        if arpLine == '':
            continue
        arpLine = arpLine.split(" ")
        if check_mac_address(arpLine[3]):
            MAC_addresses.append(arpLine[3])

    return MAC_addresses
        
def find_a_match():
    MAC_addresses= arp_table_function()
    #check if there is 2 same mac address in the arp table with 2 different ip address
    for i in MAC_addresses:
        if MAC_addresses.count(i) > 1:
            print("warning: there is 2 same mac address in the arp table with 2 different ip address")

if __name__ == "__main__":
    while True:
        find_a_match()
        time.sleep(15)
