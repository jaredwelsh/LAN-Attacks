from socket import inet_aton, IPPROTO_TCP, IPPROTO_UDP
from struct import pack, unpack


class IPv4():
    def __init__(self):
        self.id = None
        self.ihl = None
        self.ver = None
        self.tos = None
        self.len = None
        self.frg = None
        self.ttl = None
        self.src = None
        self.dst = None
        self.protr = None
        self.check = None

    def gen_message(self):
        return pack('!BBHHHBBH4s4s')

    def addr_to_bytes(self, addr):
        return inet_aton(addr)
