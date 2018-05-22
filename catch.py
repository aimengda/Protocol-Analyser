#-*-coding:-UTF-8-*-
from scapy.all import *
import socket
import dpkt
def catchPcap(amount):
    dpkt = sniff(count=10)
    wrpcap("demo.pcap",dpkt)
