#-*-coding:-UTF-8-*-
import Tkinter  
import ttk
from scapy.all import *
import dpkt
import socket
import sys  
reload(sys)  
sys.setdefaultencoding('utf8') 
  
  
def catchPcap():
    dpkt = sniff(count=40)
    wrpcap("demo.pcap",dpkt)


def IPclass():    #解析ip地址头部
    f = open('demo.pcap')
    pcap = dpkt.pcap.Reader(f)
    ipfram=Tkinter.Tk()
    ipfram.title("IP数据报解析")  
    tree=ttk.Treeview(ipfram,show="headings")#表格
    tree["columns"]=("版本号(4位)+IP头长度(4位)","服务类型","总长度","标识","DF标记位","MF标记位","偏移","生存时间","协议","首部校验和","源地址","目标地址")  
    tree.column("版本号(4位)+IP头长度(4位)",width=150)   #表示列,不显示  
    tree.column("服务类型",width=70)  
    tree.column("总长度",width=50)
    tree.column("标识",width=50)  
    tree.column("DF标记位",width=70) 
    tree.column("MF标记位",width=70)
    tree.column("生存时间",width=70)
    tree.column("协议",width=50) 
    tree.column("首部校验和",width=70)
    tree.column("源地址",width=100)  
    tree.column("目标地址",width=100) 
  
    tree.heading("版本号(4位)+IP头长度(4位)",text="版本号(4位)+IP头长度(4位)")  #显示表头  
    tree.heading("服务类型",text="服务类型")  
    tree.heading("总长度",text="总长度")  
    tree.heading("标识",text="标识")  
    tree.heading("DF标记位",text="DF标记位") 
    tree.heading("MF标记位",text="MF标记位") 
    tree.heading("偏移",text="偏移")
    tree.heading("生存时间",text="生存时间") 
    tree.heading("协议",text="协议")  
    tree.heading("首部校验和",text="首部校验和") 
    tree.heading("源地址",text="源地址")  
    tree.heading("目标地址",text="目标地址") 
 
    i=0  
    for (ts, buf) in pcap:
            # 获取以太网部分数据
            eth = dpkt.ethernet.Ethernet(buf)
            # 获取IP层数据
            ip = eth.data
            #判断是否为IP数据报
            if not isinstance(ip,dpkt.ip.IP):
                tree.insert("",i,text=i ,values=("非IP数据包类型")) #插入数据，
                i=i+1
                continue
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            protocol= ip.p   #ICMP：1，IGMP：2，TCP：6，UDP：17
            src = socket.inet_ntoa(ip.src) #源地址
            dst = socket.inet_ntoa(ip.dst) #目标地址
            if protocol == 1 :
                tree.insert("",i,text=i ,values=(hex(ip._v_hl),ip.tos,ip.len,ip.id,do_not_fragment,more_fragments,fragment_offset,ip.ttl,'ICMP',hex(ip.sum),src,dst)) #插入数据，
            elif protocol ==2 :
                tree.insert("",i,text=i ,values=(hex(ip._v_hl),ip.tos,ip.len,ip.id,do_not_fragment,more_fragments,fragment_offset,ip.ttl,'IGMP',hex(ip.sum),src,dst)) #插入数据，
            elif protocol ==6 :
                tree.insert("",i,text=i ,values=(hex(ip._v_hl),ip.tos,ip.len,ip.id,do_not_fragment,more_fragments,fragment_offset,ip.ttl,'TCP',hex(ip.sum),src,dst)) #插入数据，
            elif protocol ==17 :
                tree.insert("",i,text=i ,values=(hex(ip._v_hl),ip.tos,ip.len,ip.id,do_not_fragment,more_fragments,fragment_offset,ip.ttl,'UDP',hex(ip.sum),src,dst)) #插入数据，
            else :
                tree.insert("",i,text=i ,values=(hex(ip._v_hl),ip.tos,ip.len,ip.id,do_not_fragment,more_fragments,fragment_offset,ip.ttl,'NO',hex(ip.sum),src,dst)) #插入数据，  
            i=i+1   
    tree.pack()
    ipfram.mainloop()

if __name__ == '__main__':
    catchPcap()
    IPclass()

