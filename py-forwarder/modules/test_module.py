import __builtin__

class Extender(__builtin__.plugin_hook):

    name = "Test Module"

    def recv(self, forwarder, buffersize, flags=None):
        return super(Extender, self).recv(forwarder, buffersize, flags)

    def bind(self, address):
        super(Extender, self).bind(address)

    def connect(self, address):
        super(Extender, self).connect(address)

    def sendall(self, forwarder, data, flags=None):
        super(Extender, self).sendall(forwarder, data, flags)
