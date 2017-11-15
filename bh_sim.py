import socket
import struct

BECKHOFF_TCP_PORT = 48898   # 0xBF02
BECKHOFF_UDP_PORT = 48899   # 0xBF03
BECKHOFF_UDP_PORT2 = 48847  # 0xBECF

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', BECKHOFF_TCP_PORT))
s.listen(5)
while 1:
    print 'accepting...'
    (sock, addr) = s.accept()
    print 'connected!'
    while 1:
        print 'read message...'
        try:
            data = b''
            while len(data) < 6:
                newdata = sock.recv(6 - len(data))
                if not newdata:
                    raise ValueError("connection broken")
                data += newdata
                print 'data: %r' % data
            _zero, _size = struct.unpack('<HI', data)
            if _zero != 0:
                raise ValueError("Wrong Format (zero != 0)")
            while len(data) < _size + 6:
                data += sock.recv(_size + 6 - len(data))
                if len(data) > _size + 6:
                    print "Too much data received: %s %s %r" % (
                        len(data), _size + 6, data)
        except Exception as e:
            print "Exception reading from master:", e
            break
        print 'return message'
        data = data[:6] + data[14:22] + data[6:14] + data[22:]
        sock.sendall(data)
