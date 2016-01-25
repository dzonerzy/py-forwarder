from socket import error as socket_error


class ForwardGeneralException(socket_error):
    def __init__(self):
        self.message = "An unknown error happen"


class ForwardCannotBindAddress(ForwardGeneralException):
    def __init__(self):
        self.message = "Can't bind the selected port or unknown interface"


class ForwardUpstreamConnect(ForwardGeneralException):
    def __init__(self):
        self.message = "Can't connect to upstream port"
