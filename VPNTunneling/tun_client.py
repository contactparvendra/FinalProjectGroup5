#!/usr/bin/env python3
from scapy.all import *

import fcntl
import struct
import os
import time
import configparser

#Read the configurations 
Config = configparser.ConfigParser()
Config.read("tun_config.ini")

# Set up VPN Server details
SERVER_IP = Config.get("VPNServer", "SERVER_IP")
SERVER_PORT = int(Config.get("VPNServer", "SERVER_PORT"))

# Create a socket 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Properties for the tun interface
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tunnel%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print(f'VPN Tunnel created with Interface Name: {ifname}')
print(f'VPN Server at {SERVER_IP}:{SERVER_PORT}')

# Assigne IP to the tun interface created above
interface_ip = Config.get("ClientInterface", "IP")
os.system(f'ip addr add {interface_ip} dev {ifname}')
# Bring up the tun interface
os.system(f'ip link set dev {ifname} up')

# Add an entry to the rounting table so that the packets sent to the private network '192.168.60.0/24'
# are rounted to the the tun interface
os.system(f'ip route add {Config.get("ClientInterface", "ROUTING_TARGET")} dev {ifname}')

# Read and write packets to the tunnel
while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])

    for fd in ready:
        if fd is sock:
            # Read the UDP packets from t socket and write it to the tunnel
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print(f'From socket <==: {pkt.src} --> {pkt.dst}')
            os.write(tun, bytes(pkt))

        if fd is tun:
            # Read the UDP packets from the tunnel and send to socket
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print(f'From tunnel ==>: {pkt.src} --> {pkt.dst}')
            sock.sendto(packet, (SERVER_IP, SERVER_PORT))
