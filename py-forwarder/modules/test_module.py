import __builtin__

class Extender(__builtin__.plugin_hook):

    def recv(self, forwarder, buffersize, flags=None):
        print "MyRecv"
        return super(Extender, self).recv(forwarder, buffersize, flags)

    def bind(self, address):
        print "MyBind"
        super(Extender, self).bind(address)

    def connect(self, address):
        print "MyConnect"
        super(Extender, self).connect(address)

    def sendall(self, forwarder, data, flags=None):
        print "MySendAll"
        super(Extender, self).sendall(forwarder, data, flags)
