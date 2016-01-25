"""
Py-forwarder

Trivial port forwarder with multiple connection handling
Author: Daniele Linguaglossa
"""

import socket
import _socket
import sys
import threading
import time
import select
import argparse


class PortForwarder:
    fsock = None
    address_from = ()
    address_to = ()
    total_sent = 0
    total_received = 0
    kill_all_threads = 0
    dumpfile = None

    class ForwardGeneralException(socket.error):
        def __init__(self):
            self.message = "An unknown error happen"

    class ForwardCannotBindAddress(ForwardGeneralException):
        def __init__(self):
            self.message = "Can't bind the selected port or unknown interface"

    class ForwardUpstreamConnect(ForwardGeneralException):
        def __init__(self):
            self.message = "Can't connect to upstream port"

    def __init__(self, address_from, address_to, dumpfile=None):
        class MySocket(_socket.SocketType):
            address = None

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
                if len(data) > 0:
                    if forwarder.dumpfile is not None:
                        with open(forwarder.dumpfile, "a") as dump:
                            packet = self.Dumper(data)
                            dump.write(packet.dump())
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
                            packet = self.Dumper(data, 1)
                            dump.write(packet.dump())
                            dump.close()
                    forwarder.total_received += len(data)
                else:
                    self.shutdown(1)
                    return None
                return data

        self.dumpfile = dumpfile
        socket.socket = MySocket  # dirty hack to modify address tuple at runtime
        self.fsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.excepthook = self.selfexcept
        self.address_from = tuple(address_from.split(":"))
        self.address_to = tuple(address_to.split(":"))
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
        while not self.kill_all_threads:
            try:
                client = self.fsock.accept()
                print "[INFO] Received connection from {}".format(client[1][0])
                tsock = self.connect_upstream()
                client_thread = threading.Thread(target=self.handle_connection, args=(client[0], tsock))
                client_thread.start()
            except KeyboardInterrupt:
                print "\n[!] Byeeee"
                print "[INFO] Total byte sent {0}".format(self.total_sent)
                print "[INFO] Total byte received {0}".format(self.total_received)
                self.kill_all_threads = True
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
            if self.kill_all_threads:
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

    def selfexcept(self, exctype, value, traceback):
        if exctype in [self.ForwardCannotBindAddress, self.ForwardUpstreamConnect]:
            sys.stderr.write("[ERROR] " + value.message + "\n")
        if exctype in [self.ForwardGeneralException]:
            sys.stderr.write("[CRITICAL] " + value.message + "\n")
        sys.exit(-1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    portforwarder = parser.add_argument_group('Port Forwarding')
    portforwarder.add_argument("-f", "--from-addr",
                               help="Forward this port to another, format is <ip:port>", required=True)
    portforwarder.add_argument("-t", "--to-addr",
                               help="Port to be forwarded, format is <ip:port>", required=True)
    portforwarder.add_argument("-d", "--dump-file",
                               help="If enabled create a dump of traffic between ports", required=False)
    args = parser.parse_args()
    print "[+] Starting port forwarding ({0} => {1})".format(args.from_addr, args.to_addr)
    PortForwarder(args.from_addr, args.to_addr, args.dump_file)
