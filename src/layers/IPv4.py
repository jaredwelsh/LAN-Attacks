from socket import inet_aton, inet_ntoa
from struct import pack, unpack


class IPv4():
    ProtoType = {'tcp': 6, 'udp': 17}

    def __init__(self, iden=1000, ihl=5, ver=4, tos=0, leng=0, frg=0, ttl=255,
                 src='127.0.0.1', dst='127.0.0.1', proto='tcp', check=0,
                 byte=None):
        if byte:
            self.build_from_byte(byte)
        else:
            self.iden = iden
            self.ihl = ihl
            self.ver = ver
            self.tos = tos
            self.leng = leng
            self.frg = frg
            self.ttl = ttl
            self.src = src
            self.dst = dst
            self.proto = ProtoType[proto]
            self.check = check

    def __str__(self):
        ret = 'IPv4: \n'
        for k, v in self.__dict__.items():
            ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def build_from_byte(self, s):
        return

    def gen_message(self):
        return pack('!BBHHHBBH4s4s', ((self.ver << 4) + self.ihl), self.tos,
                    self.len, self.id, self.frg, self.ttl,
                    self.proto, self.check, addr_to_bytes(self.src),
                    addr_to_byte(self.dst))

    def addr_to_bytes(self, addr):
        return inet_aton(addr)
