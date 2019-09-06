#!/usr/bin/env python
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP \ IP range.")
    options, arguments = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for element in results_list:
        print(element["ip"] +"\t\t" + element["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)