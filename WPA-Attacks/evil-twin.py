# Evil - Twin WPA attack CLI tool
from scapy.all import *
import time
import os
from threading import Thread
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

ap_list = []
ap_to_attack = None
clients = []
client_to_attack = None
done_scanning = False


def bash(cmd):
    return os.popen(cmd).read()


def change_channel(interface):
    global done_scanning
    ch = 1
    while True and not done_scanning:
        bash(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


def callback_ap(pkt):
    # identify a new access point and add it to the list
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode()
        if bssid not in [ap[0] for ap in ap_list]:
            ap_list.append((bssid, ssid))
            print(f"\t[+] Found new access point: {bssid} {ssid}")


def scan_for_aps(interface):
    #  scan for nearby access points for 60 seconds
    channel_changer = Thread(target=change_channel, args=(interface,))
    channel_changer.daemon = True
    channel_changer.start()
    sniff(prn=callback_ap, iface=interface, timeout=10)
    global done_scanning
    done_scanning = True


def scan_for_clients(pkt):
    #  get all clients associated with access point
    global clients
    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:
            if ap_to_attack[0] == pkt.addr1:
                if pkt.type in [1, 2]:  # the type I'm looking for
                    if pkt.addr2 not in clients and pkt.addr2 != '':
                        clients.append(pkt.addr2)


def start_evil_twin(interface):
    global ap_list, clients, ap_to_attack, client_to_attack
    #  enable monitor mode
    if "mon" in interface:
        print("[*] Already in monitor mode")
    else:
        bash(f"airmon-ng start {interface}")
        interface = interface + "mon"

    #  scan for nearby access points
    print("[*] Scanning for nearby access points")
    scan_for_aps(interface)
    print(f"[*] Found {len(ap_list)} access points")

    #  prompt user for access point to attack
    print("[*] Please choose an access point to attack")
    for ap, i in zip(ap_list, range(len(ap_list))):
        print(f"\t[{i + 1}] {ap[0]} {ap[1]}")

    while True:
        i = int(input("[>] "))
        if i not in range(1, len(ap_list) + 1):
            print("[!] Please enter a valid access point")
        else:
            ap_to_attack = ap_list[i - 1]
            break

    #  get all clients of access point and prompt user for client to attack
    print("[*] Getting all clients of access point")
    sniff(iface=interface, prn=scan_for_clients, timeout=10)
    print(f"[*] Found {len(clients)} clients")
    print("[*] Please choose a client to attack")
    for client, i in zip(clients, range(len(clients))):
        print(f"\t[{i + 1}] {client}")

    while True:
        i = int(input("[>] "))
        if i not in range(1, len(clients) + 1):
            print("[!] Please enter a valid client")
        else:
            client_to_attack = clients[i - 1]
            break


def main():
    #  print welcome message
    print("[*] Welcome to Evil Twin WPA attack CLI tool")
    #  prompt user for interface
    print("[?] Enter the interface you want to use: ")
    for interface, i in zip(get_if_list(), range(len(get_if_list()))):
        print(f"\t[{i + 1}] {interface}")
    interface = ""
    while True:
        i = int(input("[>] "))
        if i not in range(1, len(get_if_list()) + 1):
            print("[!] Please enter a valid interface")
        else:
            interface = get_if_list()[i - 1]
            break
    #  start evil twin attack
    start_evil_twin(interface)


if __name__ == "__main__":
    main()
