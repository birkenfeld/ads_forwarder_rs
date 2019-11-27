import socket
import random
import time

BECKHOFF_TCP_PORT = 48898   # 0xBF02
BECKHOFF_UDP_PORT = 48899   # 0xBF03
BECKHOFF_UDP_PORT2 = 48847  # 0xBECF

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.connect(('127.0.0.1', BECKHOFF_UDP_PORT))

while True:
    print('sending...')
    rndstr = bytes([random.randrange(256) for i in range(756)])
    s.send(rndstr)
    print('receiving...')
    (msg, addr) = s.recvfrom(3072)
    assert msg == rndstr
    time.sleep(1)
