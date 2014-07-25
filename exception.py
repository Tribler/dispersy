class DispersyException(Exception):
    pass


class CommunityNotFoundException(DispersyException):
    def __init__(self, cid):
        self.cid = cid


class ConversionNotFoundException(DispersyException):
    def __init__(self, packet=None, message=None):
        self.packet = packet
        self.message = message


class MetaNotFoundException(DispersyException):
    pass
