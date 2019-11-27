import socket
import struct
import random
import time

BECKHOFF_TCP_PORT = 48898   # 0xBF02
BECKHOFF_UDP_PORT = 48899   # 0xBF03
BECKHOFF_UDP_PORT2 = 48847  # 0xBECF

mynetid = 0x0a000000 | random.randint(0, 256)
tgtnetid = 0xc0a8c901

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.connect(('127.0.0.1', BECKHOFF_TCP_PORT))
print('connected!')

while True:
    print('send request...')
    data = struct.pack('<HIIBBHIBBHHHIIIIII',
                       # AMS TCP header: 0, lenght
                       0, 0x2c,
                       # AMS Header: target NetId, Port
                       socket.htonl(tgtnetid), 1, 1, 0x320,
                       # source NetId, Port
                       socket.htonl(mynetid), 1, 1, 0x8195,
                       # command ID, state flags, length of ADS-Data
                       0x5005, 0, 12,
                       # Error Code, Invoke Id
                       0, 0,
                       # 12 Bytes of 0 (3*int32)
                       0, 0, 0xffffffff)
    sock.sendall(data)
    print('read reply')
    try:
        data = b''
        while len(data) < 6:
            newdata = sock.recv(6 - len(data))
            if not newdata:
                raise ValueError('connection broken')
            data += newdata
        _zero, _size = struct.unpack('<HI', data)
        if _zero != 0:
            raise ValueError('Wrong Format (zero != 0)')
        while len(data) < _size + 6:
            data += sock.recv(_size + 6 - len(data))
            if len(data) > _size + 6:
                print(f'Too much data received: {len(data)} {_size + 6} '
                      f'{data!r}')
    except Exception as e:
        print('Exception reading from BH:', e)
        break
    assert socket.ntohl(struct.unpack('<I', data[6:10])[0]) == mynetid
    time.sleep(1)
