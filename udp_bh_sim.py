import socket

BECKHOFF_TCP_PORT = 48898   # 0xBF02
BECKHOFF_UDP_PORT = 48899   # 0xBF03
BECKHOFF_UDP_PORT2 = 48847  # 0xBECF

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(('0.0.0.0', BECKHOFF_UDP_PORT))

while True:
    print('receiving...')
    (msg, addr) = s.recvfrom(3072)
    print('sending...')
    s.sendto(msg, addr)
