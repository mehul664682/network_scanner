#!usr/bin/env python

import scapy.all as scapy
import argparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose= False)[0]

    client_list=[]
    for element in answered_list:
        client_dic = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dic)
    return client_list


def print_result(client_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in client_list:
        print("|"+client["ip"] + "\t|\t" + client["mac"]+"|")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Provide IP range to send packet")
    options= parser.parse_args()
    return options


ip_range = get_args()
scan_result = scan(ip_range.target)
print_result(scan_result)
