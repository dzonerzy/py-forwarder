import _socket
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO


class MySocket(_socket.SocketType):
    address = None

    class HTTPRequest(object, BaseHTTPRequestHandler):
        def __init__(self, request_text):
            self.rfile = StringIO(request_text)
            self.raw_requestline = self.rfile.readline()
            self.error_code = self.error_message = None
            self.parse_request()
            super(BaseHTTPRequestHandler, self).__init__()

        def send_error(self, code, message=None):
            self.error_code = code
            self.error_message = message

    class Dumper:
        data = None
        outpacket = 0
        FILTER = "".join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])

        def __init__(self, binarydata, inpacket=0):
            self.data = binarydata
            self.inpacket = inpacket

        def dump(self, length=16):
            N = 0
            buf = "[IN PACKET]\n" if self.inpacket else "[OUT PACKET]\n"
            while self.data:
                s, self.data = self.data[:length], self.data[length:]
                hexdata = ' '.join(["%02X" % ord(x) for x in s])
                s = s.translate(self.FILTER)
                buf += "%04X   %-*s   %s\n" % (N, length * 3, hexdata, s)
                N += length
            return buf

    def connect(self, address):
        self.address = tuple([address[0], int(address[1])])
        super(MySocket, self).connect(self.address)

    def bind(self, address):
        self.address = tuple([address[0], int(address[1])])
        super(MySocket, self).bind(self.address)

    def sendall(self, forwarder, data, flags=None):
        if forwarder.dumphttp:
            try:
                request = self.HTTPRequest(data)
                if request.command in ["GET", "POST"]:
                    print "[HTTP] {} => {}".format(request.command,
                                                   request.headers.getheader("host"))
            except AttributeError:
                pass  # skip maybe HTTPS or malformed
        if len(data) > 0:
            if forwarder.dumpfile is not None:
                with open(forwarder.dumpfile, "a") as dump:
                    if forwarder.dumpformat == "HEX":
                        packet = self.Dumper(data)
                        dump.write(packet.dump())
                    elif forwarder.dumpformat == "RAW":
                        dump.write(data)
                    dump.close()
            forwarder.total_sent += len(data)
        else:
            self.shutdown(1)
            return None
        super(MySocket, self).sendall(data, 0)

    def recv(self, forwarder, buffersize, flags=None):
        data = super(MySocket, self).recv(buffersize, 0)
        if len(data) > 0:
            if forwarder.dumpfile is not None:
                with open(forwarder.dumpfile, "a") as dump:
                    if forwarder.dumpformat == "HEX":
                        packet = self.Dumper(data, 1)
                        dump.write(packet.dump())
                    elif forwarder.dumpformat == "RAW":
                        dump.write(data)
                    dump.close()
            forwarder.total_received += len(data)
        else:
            self.shutdown(1)
            return None
        return data
