# _*_ coding=utf-8 _*_
from Tkinter import *
import ttk
from scapy.all import *
import dpkt
import Tkinter 
import binascii
import os
import struct
import time
import select 
import socket
import graphics  
import sys 
reload(sys)  
sys.setdefaultencoding('utf8')  

top =Tk()
top.title("Protocol Analyser")
top.maxsize(800, 600)  
top.minsize(400, 300) 

def catchPcap():#抓包
    dpkt = sniff(count=20)
    wrpcap("demo.pcap",dpkt)

def pack_callback(packet):
#     print packet.show()  #可以查看包的结构属性等
    if packet["TCP"].payload:  #检测tcp负载是否有数据，有Ethernet、IP、TCP几个阶段
        appstr=str(packet["TCP"].payload)  #将tcp负载字节数组转化为字符串
        #匹配自定义正则表达式
        pat = 'Content-Type:(.*)[;\r\n]'   #创建一个正则表达式
        #在字符串中匹配这个正则表达式
        #这里以Content-Type:开头，以;或\r结尾的
        pat = re.compile(pat);   #使用正则表达式，创建正则对象
        m = re.search(pat,appstr)  #查询是否存在匹配的子字符串
        if m:
            print(m.groups())  #打印需要()输出的内容

def Macclass():   
    catchPcap()
    f = open("demo.pcap","rb")
    pcap = dpkt.pcap.Reader(f)

    mac=Tkinter.Tk()
    mac.title("Ethernet帧头部解析")  
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

def IPclass():    #解析ip地址头部
    catchPcap()
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

ICMP_ECHO_REQUEST = 8

def checksum(str): 
    csum = 0
    countTo = (len(str) / 2) * 2
    
    count = 0
    while count < countTo:
        thisVal = ord(str[count+1]) * 256 + ord(str[count]) 
        csum = csum + thisVal 
        csum = csum & 0xffffffffL  
        count = count + 2
    
    if countTo < len(str):
        csum = csum + ord(str[len(str) - 1])
        csum = csum & 0xffffffffL
    
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum 
    answer = answer & 0xffff 
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer 
    
def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    
    while 1: 
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return "Request timed out."
    
        timeReceived = time.time() 
        recPacket, addr = mySocket.recvfrom(1024)
        
        # Fetch the ICMPHeader fromt the IP
        icmpHeader = recPacket[20:28]
        rawTTL = struct.unpack("s", recPacket[8])[0]  
        # binascii -- Convert between binary and ASCII  
        TTL = int(binascii.hexlify(str(rawTTL)), 16)
        
        icmpType, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
        
        print icmpType
        print code

        if packetID == ID:
            bytes = struct.calcsize("d") 
            timeSent = struct.unpack("d", recPacket[28:28 + bytes])[0]
            return (destAddr, len(recPacket), (timeReceived - timeSent)*1000, TTL)
        
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."

    
def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff		
    else:
        myChecksum = htons(myChecksum)
        
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.
    
def doOnePing(destAddr, timeout): 
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw

    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    
    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    
    mySocket.close()
    return delay
    
def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)

    icmpfra=Tkinter.Tk()
    icmpfra.title("Pinging " + dest + " using Python:")  
    tree=ttk.Treeview(icmpfra,show="headings")#表格
    tree["columns"]=("Reply from","bytes","time","TTL")  
    tree.column("Reply from",width=100)   #表示列,不显示  
    tree.column("bytes",width=50)  
    tree.column("time",width=100)
    tree.column("TTL",width=50)

    tree.heading("Reply from",text="Reply from")  #显示表头  
    tree.heading("bytes",text="bytes")  
    tree.heading("time",text="time")
    tree.heading("TTL",text="TTL")
    k=0
    cou=0
    # Send ping requests to a server separated by approximately one second
    while cou<4 :
        delay=doOnePing(dest, timeout)
        cou=cou+1
        tree.insert("",k,text=k,values=(delay))
        time.sleep(1)# one second
    tree.pack()
    icmpfra.mainloop()
    return delay



flit=ttk.Button(top,text='过滤',command=pack_callback)
flit.pack()

label = Label(top,width = 10,height = 5,text = '请输入网址')
label.pack()

e=ttk.Entry(top)
e.pack()
web=e.get

ethan=ttk.Button(top,text='Ethernet帧头部解析',command=Macclass)
ethan.pack()

ipana=ttk.Button(top,text='IP数据报头部解析',command=IPclass)
ipana.pack()

icmpana=ttk.Button(top,text='ICMP报文解析',command=ping(web))
icmpana.pack()

top.mainloop()
