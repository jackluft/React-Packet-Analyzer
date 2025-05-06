from scapy.all import *
from fastapi.responses import JSONResponse
from detect_ddos import analyze_network_traffic
def get_ips(packets):
    ip_list = []
    for p in packets:
        src_ip = -1
        if IP in p:
            src_ip = p[IP].src
        elif IPv6 in p:
            src_ip = p[IPv6].src
        
        if(src_ip != -1 and src_ip not in ip_list):
            ip_list.append(src_ip)
    
    return JSONResponse(content={"data":ip_list}, status_code=200)
def ip_list(file_path):
    #Func: ip_list
    #args: file_path -> File location
    #Docs: This function will return a list of all the IP addresses in the pcap file
    try:
        packets = rdpcap(file_path)
        if len(packets) == 0:
            return JSONResponse(content={"Warning":"PCAP file is empty"}, status_code=200)

    except scapy.error.Scapy_Exception as e:
        print(e)
        return JSONResponse(content={"ERROR":"Unable to read PCAP file"}, status_code=500)
    return get_ips(packets)
def analyse_ddos(file_path):
    #func: detect_ddos
    #args: file_path -> 
    #Docs: This function will detect DDoS attacks 
    try:
        packets = rdpcap(file_path)
        if len(packets) == 0:
            return JSONResponse(content={"Warning":"PCAP file is empty"}, status_code=200)

    except scapy.error.Scapy_Exception as e:
        print(e)
        return JSONResponse(content={"ERROR":"Unable to read PCAP file"}, status_code=500)
    #No errors reading the file
    #continue calculations
    data = {
    "tcp_list": [],
    "udp_list": [],
    "icmp_list": []
    }
    for p in packets:
        packet_content = list(expand(p))
        if p.haslayer(TCP) and p.haslayer(IP):
            #tcp IPv4
            data["tcp_list"].append(p)

        elif p.haslayer(IP) and "ICMP" in packet_content:
            #ICMP packet <-(p.haslayer(ICMP) is not working)->
            data["icmp_list"].append(p)
        elif "UDP" in packet_content:	
            #udp
            data["udp_list"].append(p)
    results = analyze_network_traffic(data)
    return JSONResponse(content=results, status_code=200)

def packetDetails(packet,protocol):
    #func: packetDetails
    #args: 
    #Docs: This function will return a object with all the packet details.
    if(protocol == "TCP"):
        #Get ports
        #Get flags 
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        return {"src_port":src_port, "dst_port":dst_port,"flags":str(flags)}
    elif(protocol == "QUIC"):
        #Get port
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        return {"src_port":src_port, "dst_port":dst_port}
    elif (protocol == "UDP"):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        return {"src_port":src_port, "dst_port":dst_port}
    
    return {}


def createPacketObject(packet,protocol):
    #func: createPacketObject
    #args: packet -> One scapy packet object
    #Docs: This function will return a packet object
    packet_object = {}
    packet_object["protocol"] = protocol
    packet_object["Packet_size"] = len(packet)
    if hasattr(packet,"payload") and len(packet.payload) > 0:
        payload = packet.payload
        packet_object["payload_size"] = len(packet.payload)
    if(IP in packet):
        packet_object["IP-Type"] = "IPv4"
        packet_object["src_IP"] = packet[IP].src
        packet_object["dst_IP"] = packet[IP].dst
        packet_object["time"] = float(packet.time)

    elif IPv6 in packet:
        packet_object["IP-Type"] = "IPv6" 
        packet_object["src_IP"] = packet[IPv6].src
        packet_object["dst_IP"] = packet[IPv6].dst
        packet_object["time"] = float(packet.time)
    
    #Check if has Ethernet layer
    if packet.haslayer(Ether):
        ether_layer = packet.getlayer(Ether)
        src_mac = ether_layer.src
        dst_mac = ether_layer.dst

        packet_object["src_mac"] = src_mac
        packet_object["dst_mac"] = dst_mac
    #Check if TCP or UDP (Add port numbers to object)
    packet_object["packet_content"] = packetDetails(packet,protocol)

    return packet_object
def expand(x):
	#func: expand
	#args: x -> x is the packet
	#Docs: This function will return the content of the packet
	#This function was from: https://stackoverflow.com/questions/13549294/get-all-the-layers-in-a-packet
	yield x.name
	while x.payload:
		x = x.payload
		yield x.name
def extractPackets(packets):
    #func: extractPackets
    #args: packets -> Array of packets
    #Docs: This function will extract all the pacekts in the pcap file
    data = [
    {
        "size":len(packets),
        "DNS-Size": 0,
        "QUIC-Size": 0,
        "MDNS-Size": 0,
        "ARP-Size": 0,
        "HTTP-Size": 0,
        "TCP-Size": 0,
        "ICMP-Size": 0,
        "UDP-Size": 0,
        "OTHER-Size": 0
    },
    {
        "Packets": []
    }
    ]
    for p in packets:
        packet_content = list(expand(p))
        print(p)
		#check the types of packets
        if p.haslayer(DNS):
            #dns    
            data[1]["Packets"].append(createPacketObject(p,"DNS"))
            data[0]["DNS-Size"] = data[0]["DNS-Size"] +1
        elif p.haslayer(UDP) and (p[UDP].dport == 443 or p[UDP].sport == 443):
            #quic
            data[1]["Packets"].append(createPacketObject(p,"QUIC"))
            data[0]["QUIC-Size"] = data[0]["QUIC-Size"] +1
        elif p.haslayer(UDP) and (p[UDP].sport == 5353 or p[UDP].dport == 5353): #and p.haslayer(DNS):
            #MDNS
            data[1]["Packets"].append(createPacketObject(p,"MDNS"))
            data[0]["MDNS-Size"] = data[0]["MDNS-Size"] +1
        elif p.haslayer(ARP):
            #arp
            data[1]["Packets"].append(createPacketObject(p,"ARP"))
            data[0]["ARP-Size"] = data[0]["ARP-Size"] +1
        elif p.haslayer(TCP) and (p[TCP].sport == 80 or p[TCP].dport == 80):
            #http
            data[1]["Packets"].append(createPacketObject(p,"HTTP"))
            data[0]["HTTP-Size"] = data[0]["HTTP-Size"] +1
        elif p.haslayer(TCP) and p.haslayer(IP):
			#tcp IPv4
            data[1]["Packets"].append(createPacketObject(p,"TCP"))
            data[0]["TCP-Size"] = data[0]["TCP-Size"] +1 
        elif p.haslayer(IP) and "ICMP" in packet_content:
			#ICMP packet <-(p.haslayer(ICMP) is not working)->
			#ERROR is very weird could not understand why it did not work
            data[1]["Packets"].append(createPacketObject(p,"ICMP"))
            data[0]["ICMP-Size"] = data[0]["ICMP-Size"] +1
        elif "UDP" in packet_content:	
            #udp
            data[1]["Packets"].append(createPacketObject(p,"UDP"))
            data[0]["UDP-Size"] = data[0]["UDP-Size"] +1
        else:
            #other packets
            data[1]["Packets"].append(createPacketObject(p,"other"))
            data[0]["OTHER-Size"] = data[0]["OTHER-Size"] +1
    return JSONResponse(content={"data":data}, status_code=200)

        
def readFile(filename):
    #func: readFile
    #args: filename -> Path of the pcap file
    #Docs: This function will read the pcap file and return all the packets in json format
    #This function will read the pcap file
    try:
        packets = rdpcap(filename)
        if len(packets) == 0:
            return JSONResponse(content={"Warning":"PCAP file is empty"}, status_code=200)

    except scapy.error.Scapy_Exception as e:
        print(e)
        return JSONResponse(content={"ERROR":"Unable to read PCAP file"}, status_code=500)
    
    #Extract all the packets
    return extractPackets(packets)

