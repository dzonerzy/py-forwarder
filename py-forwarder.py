"""

Py-forwarder

Trivial port forwarder with multiple connection handling and packets dump
Author: Daniele Linguaglossa

check out for updates on https://github.com/dzonerzy/py-forwarder

"""
import BaseHTTPServer
import StringIO
import socket
import _socket
import sys
import threading
import time
import select
import argparse
import Queue


class PortForwarder:
    fsock = None
    address_from = ()
    address_to = ()
    total_sent = 0
    total_received = 0
    event = threading.Event()
    dumpfile = None
    dumpformat = None
    dumphttp = False
    know_client = []
    printqueue = Queue.Queue(0)

    class ForwardGeneralException(socket.error):
        def __init__(self):
            self.message = "An unknown error happen"

    class ForwardCannotBindAddress(ForwardGeneralException):
        def __init__(self):
            self.message = "Can't bind the selected port or unknown interface"

    class ForwardUpstreamConnect(ForwardGeneralException):
        def __init__(self):
            self.message = "Can't connect to upstream port"

    def __init__(self, config):
        class MySocket(_socket.SocketType):
            address = None

            class HTTPRequest(BaseHTTPServer.BaseHTTPRequestHandler):
                def __init__(self, request_text):
                    self.rfile = StringIO.StringIO(request_text)
                    self.raw_requestline = self.rfile.readline()
                    self.error_code = self.error_message = None
                    self.parse_request()

                def send_error(self, code, message):
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
        self.dumphttp = config.dump_http_req if config.dump_http_req is not None else None
        self.dumpfile = config.dump_file if config.dump_file is not None else None
        self.dumpformat = config.dump_format if config.dump_format is not None else None
        socket.socket = MySocket  # dirty hack to modify address tuple at runtime
        self.fsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.excepthook = self.self_except
        self.address_from = tuple(config.from_addr.split(":"))
        self.address_to = tuple(config.to_addr.split(":"))
        self.fsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.fsock.bind(self.address_from)
        except socket.error:
            raise self.ForwardCannotBindAddress()
        self.serve()

    def retry(self, times, sleep):
        while times:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(self.address_to)
                return sock
            except socket.error:
                time.sleep(sleep)
                times -= 1
                sys.stderr.write("[-] Retrying to connect to upstream port {0}\n".format(self.address_to[1]))
        raise self.ForwardUpstreamConnect()

    def serve(self):
        self.fsock.listen(1)
        while not self.event.isSet():
            try:
                client = self.fsock.accept()
                if client[1][0] not in self.know_client:
                    print "[*] Received connection from {}".format(client[1][0])
                    self.know_client.append(client[1][0])
                tsock = self.connect_upstream()
                client_thread = threading.Thread(target=self.handle_connection, args=(client[0], tsock))
                client_thread.start()
            except KeyboardInterrupt:
                print "\n[!] Byeeee"
                print "[INFO] Total bytes sent {0}".format(self.total_sent)
                print "[INFO] Total bytes received {0}".format(self.total_received)
                self.event.set()
            except self.ForwardUpstreamConnect():
                raise self.ForwardUpstreamConnect()

    def connect_upstream(self):
        tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tsock.connect(self.address_to)
        except socket.error:
            tsock = self.retry(5, 2)
        return tsock

    def handle_connection(self, clientsock, tsock):
        inputs = [clientsock, tsock]
        while True:
            if self.event.isSet():
                return
            try:
                read_ready, write_ready, ex_ready = select.select(inputs, inputs, [])
                for sock in read_ready:
                    sock.setblocking(0)
                    try:
                        if sock == clientsock:
                            tsock.sendall(self, clientsock.recv(1024))
                        if sock == tsock:
                            clientsock.sendall(tsock.recv(self, 1024))
                    except socket.error:
                        clientsock.shutdown(1)
                        tsock.shutdown(1)
                        return
            except Exception:
                return

    def self_except(self, exc_type, value, traceback):
        if exc_type in [self.ForwardCannotBindAddress, self.ForwardUpstreamConnect]:
            sys.stderr.write("[ERROR] " + value.message + "\n")
        if exc_type in [Exception]:
            sys.stderr.write("[CRITICAL] " + value.message + "\n")
        sys.exit(-1)

    def print_queue(self):
        pass

def dump_format(v):
    if v in ["RAW", "HEX"]:
        return v
    else:
        raise argparse.ArgumentTypeError("String '%s' does not match required format" % (v,))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    portforwarder = parser.add_argument_group('Port Forwarding')
    portforwarder.add_argument("-f", "--from-addr",
                               help="Forward this port to another, format is <ip:port>", required=True)
    portforwarder.add_argument("-t", "--to-addr",
                               help="Port to be forwarded, format is <ip:port>", required=True)
    dumper = parser.add_argument_group('Packet dump')
    dumper.add_argument("-d", "--dump-file",
                        help="If enabled create a dump of traffic between ports", required=False)
    dumper.add_argument("-df", "--dump-format", type=dump_format,
                        help="Format are RAW or HEX", required=False)
    packet = parser.add_argument_group('Packet inspector')
    packet.add_argument("--dump-http-req", action='store_true',
                        help="If enabled show a small dump about each HTTP request", required=False)
    args = parser.parse_args()
    if args.dump_file and args.dump_format is None:
        parser.error("Switch -d require a format, use -df to specify one.")
    print "[!] Starting port forwarding ({0} => {1})".format(args.from_addr, args.to_addr)
    PortForwarder(args)
