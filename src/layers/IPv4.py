from socket import inet_aton, inet_ntoa
from struct import pack, unpack_from

# add dscp, ecn, and, flags


class IPv4():
    ProtoType = {'tcp': 6, 'udp': 17}

    def __init__(self, iden=1000, ihl=5, ver=4, tos=0, leng=0, frag=0, ttl=255,
                 src='127.0.0.1', dst='127.0.0.1', proto='tcp', check=0,
                 byte=None):
        if byte:
            self.build_from_byte(byte)
        else:
            self.ver = ver
            self.ihl = ihl
            self.tos = tos
            self.leng = leng
            self.iden = iden
            self.frag = frag
            self.ttl = ttl
            self.proto = self.ProtoType[proto]
            self.check = check
            self.src = src
            self.dst = dst

    def __str__(self):
        ret = 'IPv4: \n'
        for k, v in self.__dict__.items():
            ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def build_from_byte(self, s):
        self.ver = unpack_from('>B', s, 0)[0] >> 4
        self.ihl = unpack_from('>B', s, 0)[0] - (self.ver << 4)
        self.tos = unpack_from('>B', s, 1)[0]
        self.leng = unpack_from('>H', s, 2)[0]
        self.iden = unpack_from('>H', s, 4)[0]
        self.frag = unpack_from('>H', s, 6)[0]
        self.ttl = unpack_from('>B', s, 8)[0]
        self.proto = unpack_from('>B', s, 9)[0]
        self.check = unpack_from('>H', s, 10)[0]
        self.src = inet_ntoa(s[12:16])
        self.dst = inet_ntoa(s[16:20])

    def gen_message(self):
        return pack('!BBHHHBBH4s4s', ((self.ver << 4) + self.ihl), self.tos,
                    self.leng, self.iden, self.frag, self.ttl,
                    self.proto, self.check, self.addr_to_bytes(self.src),
                    self.addr_to_bytes(self.dst))

    def addr_to_bytes(self, addr):
        return inet_aton(addr)
