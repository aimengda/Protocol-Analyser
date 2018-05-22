#-*-coding:-UTF-8-*-
from scapy.all import *
import dpkt
import socket
import prettytable as pt
import sys  
reload(sys)  
sys.setdefaultencoding('utf8')  
def catchpacp():    #抓包
   dpkt  = sniff(count = 20)
   wrpcap("demo.pcap", dpkt)

def IPclass():    #解析ip地址头部
    f = open('demo.pcap')
    pcap = dpkt.pcap.Reader(f)
    tb = pt.PrettyTable()
    tb.field_names = ["版本号(4位)+IP头长度(4位)","服务类型","总长度","标识","DF标记位","MF标记位","生存时间","协议","首部校验和","源地址","目标地址"]
    tb.align["版本号(4位)+IP头长度(4位)"] = "c" # Left align city names  
    tb.padding_width = 1 # One space between column edges and contents (default)   
    for (ts, buf) in pcap:
            # 获取以太网部分数据
            eth = dpkt.ethernet.Ethernet(buf)
            # 获取IP层数据
            ip = eth.data
            #判断是否为IP数据报
            if not isinstance(ip,dpkt.ip.IP):
                print '非IP数据包类型'
                continue
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            protocol= ip.p   #ICMP：1，IGMP：2，TCP：6，UDP：17
            src = socket.inet_ntoa(ip.src) #源地址
            dst = socket.inet_ntoa(ip.dst) #目标地址
            if protocol == 1 :
                tb.add_row([hex(ip._v_hl),ip.tos,ip.len,ip.id,do_not_fragment,more_fragments,ip.ttl,'ICMP',hex(ip.sum),src,dst])
            elif protocol ==2 :
                tb.add_row([hex(ip._v_hl),ip.tos, ip.len, ip.id,do_not_fragment,more_fragments,ip.ttl,'IGMP',hex(ip.sum),src,dst])
            elif protocol ==6 :
                tb.add_row([hex(ip._v_hl),ip.tos, ip.len, ip.id,do_not_fragment,more_fragments,ip.ttl,'TCP',hex(ip.sum),src,dst])
            elif protocol ==17 :
                tb.add_row([hex(ip._v_hl),ip.tos, ip.len, ip.id,do_not_fragment,more_fragments,ip.ttl,'UDP',hex(ip.sum),src,dst])
            else :
                tb.add_row([hex(ip._v_hl),ip.tos, ip.len, ip.id,do_not_fragment,more_fragments,ip.ttl,'NO',hex(ip.sum),src,dst])     
    print tb

if __name__ == '__main__':
    catchpacp()
    IPclass()
