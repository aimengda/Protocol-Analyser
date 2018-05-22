# _*_ coding=utf-8 _*_
from socket import *
import os
import sys
import struct
import time
import select
import binascii  
import graphics
import Tkinter  
import ttk

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
    
ping("baidu.com")

