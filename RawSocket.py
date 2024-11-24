from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.http import HTTP

output = open('output/testoutput.txt', 'w',encoding='utf-8')

def packet_callback(packet):

    
    
    IP, TCP, UDP in packet
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        Prt = packet[IP].proto
        Len = packet[IP].len

    if TCP in packet:
        tcp_src_port = packet[TCP].sport
        tcp_dst_port = packet[TCP].dport
        tcp_seq = packet[TCP].seq
        tcp_ack = packet[TCP].ack

    if UDP in packet:
        udp_src_port = packet[UDP].sport
        udp_dst_port = packet[UDP].dport
        udp_checksum = packet[UDP].chksum
        udp_datagram_length = packet[UDP].len

    # Application Layer Protocol Detection
    if packet.haslayer(HTTPRequest):
        Req_url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        Req_method = packet[HTTPRequest].Method.decode()

        print(f"\n[IP Header] Source IP: {ip_src}, Destination IP: {ip_dst}, Length: {Len}, PrtNum: {Prt}")
        output.write("[IP Header] Source IP:" + ip_src + " Destination IP:" + ip_dst + " Length:"+ str(Len) + " PrtNum:"+ str(Prt) + "\n")

        print(f"[TCP Header] Source Port: {tcp_src_port}, Destination Port: {tcp_dst_port}, Sequence No: {tcp_seq}, Acknowledgement No: {tcp_ack}")
        output.write("[TCP Header] Source Port:" + str(tcp_src_port) + " Destination Port:" + str(tcp_dst_port) + " Sequence No:" + str(tcp_seq) + " Acknowledgement No:" + str(tcp_ack) + "\n")

        print(f"[Application Layer] Protocol: HTTP/1.1 {Req_method} Request {Req_url}")
        output.write("[Application Layer] Protocol: HTTP/1.1 "+ Req_method + " Request " + Req_url + "\n")
        output.write("\n------------------------------------------------------------------------------------\n\n") 
        
    elif packet.haslayer(HTTPResponse):
        Res_status = packet[HTTPResponse]

        print(f"\n[IP Header] Source IP: {ip_src}, Destination IP: {ip_dst}, Length: {Len}, PrtNum: {Prt}")
        output.write("[IP Header] Source IP:" + ip_src + " Destination IP:" + ip_dst + " Length:"+ str(Len) + " PrtNum:"+ str(Prt) + "\n")

        print(f"[TCP Header] Source Port: {tcp_src_port}, Destination Port: {tcp_dst_port}, Sequence No: {tcp_seq}, Acknowledgement No: {tcp_ack}")
        output.write("[TCP Header] Source Port:" + str(tcp_src_port) + " Destination Port:" + str(tcp_dst_port) + " Sequence No:" + str(tcp_seq) + " Acknowledgement No:" + str(tcp_ack) + "\n")


        print(f"[Application Layer] Protocol: HTTP/1.1 {Res_status} Response")
        output.write("[Application Layer] Protocol: HTTP/1.1 "+ str(Res_status) + " Response")
        output.write("\n------------------------------------------------------------------------------------\n\n") 
    # elif packet.haslayer()
    if packet.haslayer(DNS):
        dns_transid = packet[DNS].id #DNS Transaction ID
        dns_query = packet[DNSQR].qname.decode() #DNS QUERY
        dns_quetype = packet[DNSQR].qtype # DNS QUETYPE
        
        if packet[DNS].qr == 0:  # DNS Query
            

            print(f"\n[IP Header] Source IP: {ip_src}, Destination IP: {ip_dst}, Length: {Len}, PrtNum: {Prt}")
            output.write("[IP Header] Source IP:" + ip_src + " Destination IP:" + ip_dst + " Length:"+ str(Len) + " PrtNum:"+ str(Prt) + "\n")

            print(f"[UDP Header] Source Port: {udp_src_port}, Destination Port: {udp_dst_port}, Checksum: {udp_checksum}, DatagramLength: {udp_datagram_length}")
            output.write("[UDP Header] Source Port:" + str(udp_src_port) + " Destination Port:" + str(udp_dst_port) +" Checksum:"+ str(udp_checksum)+ " DatagramLength:"+ str(udp_datagram_length) +"\n")

            print(f"[Application Layer] Protocol: DNS, Query: {dns_query}, Quetype: {dns_quetype}, Transaction ID: {dns_transid}")
            output.write("[Application Layer] Protocol: DNS, Query:" + dns_query + " Quetype:"+ str(dns_quetype) + " Transaction ID:" + str(dns_transid) + "\n")
            output.write("\n------------------------------------------------------------------------------------\n\n") 

        elif packet[DNS].qr == 1:  # DNS Response

            print(f"\n[IP Header] Source IP: {ip_src}, Destination IP: {ip_dst}, Length: {Len}, PrtNum: {Prt}")
            output.write("[IP Header] Source IP:" + ip_src + " Destination IP:" + ip_dst + " Length:"+ str(Len) + " PrtNum:"+ str(Prt) + "\n")

            print(f"[UDP Header] Source Port: {udp_src_port}, Destination Port: {udp_dst_port}, Checksum: {udp_checksum}, DatagramLength: {udp_datagram_length}")
            output.write("[UDP Header] Source Port:" + str(udp_src_port) + " Destination Port:" + str(udp_dst_port) +" Checksum:"+ str(udp_checksum)+ " DatagramLength:"+ str(udp_datagram_length) +"\n")

            print(f"[Application Layer] Protocol: DNS, Response, Quetype: {dns_quetype}, Transaction ID: {dns_transid}")
            output.write("[Application Layer] Protocol: DNS, Response"+ " Quetype:"+ str(dns_quetype) + " Transaction ID:" + str(dns_transid) + "\n")
            output.write("\n------------------------------------------------------------------------------------\n\n") 
                      

# print("패킷 캡처 시작: 1")
# while True:
#     start = input()
#     if start == "1":
#         break

# Capture packets with a filter for IP packets with TCP/UDP protocols
print("Starting packet capture...")
sniff(filter="ip", prn=packet_callback, store=0)
output.close()