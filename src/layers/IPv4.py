from socket import inet_aton, inet_ntoa
from struct import pack, unpack_from, unpack

# add dscp, ecn, and, flags


class IPv4():
    ProtoType = {'tcp': 6, 'udp': 17, 'icmp': 1, 'igmp': 2, 'encap': 41}

    def __init__(self, iden=1000, ihl=5, ver=4, tos=0, tlen=20, frag=0,
                 ttl=255, src='127.0.0.1', dst='127.0.0.2', proto='tcp',
                 check=0, from_bytes=None):
        self.layer = 'l2'
        if from_bytes:
            self.msg = from_bytes
            self.build_from_byte(from_bytes)
        else:
            self.ver = ver
            self.ihl = ihl
            self.tos = tos
            self.tlen = tlen
            self.iden = iden
            self.frag = frag
            self.ttl = ttl
            self.proto = self.ProtoType[proto]
            self.check = check
            self.src = src
            self.dst = dst
            self.msg = None

    def __str__(self):
        ret = 'IPv4: \n'
        for k, v in self.__dict__.items():
            if k in ('check', 'iden'):
                ret += '\t{}: {}\n'.format(k, hex(v))
            elif k not in ('msg', 'layer'):
                ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def type(self):
        return "IPv4"

    def build_from_byte(self, byte):
        unpck = unpack('>BBHHHBBH', byte[:12])
        self.ver = unpck[0] >> 4
        self.ihl = unpck[0] & 7
        self.tos = unpck[1]
        self.tlen = unpck[2]
        self.iden = unpck[3]
        self.frag = unpck[4]
        self.ttl = unpck[5]
        self.proto = unpck[6]
        self.check = unpck[7]
        self.src = inet_ntoa(byte[12:16])
        self.dst = inet_ntoa(byte[16:20])

    def gen_message(self):
        l_half = pack('!BBHHHBB', (self.ver << 4) + self.ihl, self.tos,
                      self.tlen, self.iden, self.frag, self.ttl, self.proto)
        r_half = pack('!4s4s', inet_aton(self.src), inet_aton(self.dst))
        self.gen_sum([l_half, r_half])
        self.msg = l_half + pack('<H', self.check) + r_half
        return self.msg

    def raw_bytes(self):
        if self.msg is None:
            self.gen_message()
        ret = ''
        hx = self.msg.hex()
        for i in range(0, len(hx), 2):
            ret += hx[i:i+2] + ' '
            if (i+2) % 16 == 0 and (i+2) % 32 != 0 and i != 0:
                ret += ' '
            elif (i+2) % 32 == 0 and i != 0:
                ret += '\n'
        return ret

    def psuedo_header(self):
        return pack('!4s4sxB', inet_aton(self.src), inet_aton(self.dst),
                    self.proto), self.tlen

    def set_tlen(self, tlen):
        self.tlen = tlen + self.ihl * 4

    def gen_sum(self, halves):
        self.check = 0
        for half in halves:
            for i in range(0, len(half), 2):
                if (i+1) < len(half):
                    self.check += half[i] + (half[i+1] << 8)
                elif (i+1) == len(half):
                    self.check += half[i]
        self.check = ((self.check + (self.check >> 16)) & 0xffff) ^ 0xffff
