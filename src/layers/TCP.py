from struct import pack, unpack


class TCP():

    FlagType = {'F': 0x01, 'S': 0x02, 'P': 0x08, 'A': 0x10,
                'U': 0x20, 'E': 0x40, 'C': 0x80}

    def __init__(self, src=0, dst=0, seq=0, ack=1, off=5, flg='', wndw=256,
                 check=None, urg=0, opt=None, from_bytes=None):
        if from_bytes:
            self.build_from_byte(from_bytes)
        else:
            self.src = src
            self.dst = dst
            self.seq = seq
            self.ack = ack
            self.off = off
            self.flg = flg
            self.wndw = wndw
            self.check = check
            self.urg = urg
            self.opt = opt

    def __str__(self):
        ret = 'TCP: \n'
        for k, v in self.__dict__.items():
            ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def build_from_byte(self, s):
        unpck = unpack('>HHIIHHHH', s)
        self.src = unpck[0]
        self.dst = unpck[1]
        self.seq = unpck[2]
        self.ack = unpck[3]
        self.off = unpck[4] >> 12
        self.flg = self.gen_byte_flag(unpck[4] & 0x1FF)
        self.wndw = unpck[5]
        self.check = unpck[6]
        self.urg = unpck[7]

    def gen_message(self):
        return pack('!HHIIHHHH', self.src, self.dst, self.seq, self.ack,
                    (self.off << 12) + self.gen_flag_byte(), self.wndw,
                    self.check, self.urg)

    def gen_byte_flag(self, flags):
        ret = ''
        for k, v in self.FlagType.items():
            if flags & v:
                ret += k
        return ret

    def gen_flag_byte(self):
        flg = 0
        for a in self.flg:
            flg += self.FlagType[a]
        return flg

