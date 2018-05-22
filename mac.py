#!/usr/bin/env python
# _*_ coding=utf-8 _*_
import Tkinter  
import ttk
import socket
import binascii
import dpkt
from scapy.all import *
import sys 
reload(sys)  
sys.setdefaultencoding('utf8')  

def catchPcap():
    dpkt = sniff(count=40)
    wrpcap("demo.pcap",dpkt)

def Macclass():   

    f = open("demo.pcap","rb")
    pcap = dpkt.pcap.Reader(f)

    mac=Tkinter.Tk()
    mac.title("Enthernet帧头部解析")  
    tree=ttk.Treeview(mac,show="headings")#表格
    tree["columns"]=("源Mac地址","目的Mac地址","类型")  
    tree.column("源Mac地址",width=150)   #表示列,不显示  
    tree.column("目的Mac地址",width=150)  
    tree.column("类型",width=50)

    tree.heading("源Mac地址",text="源Mac地址")  #显示表头  
    tree.heading("目的Mac地址",text="目的Mac地址")  
    tree.heading("类型",text="类型")  
    j=0
    for (ts,buf) in pcap:
        ethheader = buf[0:14]
        dstmac = binascii.b2a_hex(ethheader[0:6])
        srcmac = binascii.b2a_hex(ethheader[6:12])
        netlayer_type = binascii.b2a_hex(ethheader[12:14])
        tree.insert("",j,text=j,values=(srcmac,dstmac,netlayer_type)) #插入数据，
    tree.pack()
    mac.mainloop()
    
if __name__ == '__main__':
    catchPcap()
    Macclass()
