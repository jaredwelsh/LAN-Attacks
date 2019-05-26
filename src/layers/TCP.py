from struct import pack, pack_into, unpack, unpack_from


# ADD OPTIONS/CALCULATE HEADER LENGTH
class TCP():

    FlagType = {'F': 0x01, 'S': 0x02, 'P': 0x08, 'A': 0x10,
                'U': 0x20, 'E': 0x40, 'C': 0x80}
    OptionType = {}

    def __init__(self, src=1024, dst=2048, seq=0, ack=1, lng=5, flg='',
                 wndw=256, check=0, urg=0, opt=None, from_bytes=None):
        self.layer = 'l3'
        if from_bytes:
            self.msg = from_bytes
            self.build_from_byte(from_bytes)
        else:
            self.src = src
            self.dst = dst
            self.seq = seq
            self.ack = ack
            self.lng = lng
            self.flg = flg
            self.wndw = wndw
            self.check = check
            self.urg = urg
            self.opt = opt
            self.msg = None

    def __str__(self):
        ret = 'tcp: \n'
        for k, v in self.__dict__.items():
            if k != 'msg':
                ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1] + '\n'

    def type(self):
        return "TCP"

    def build_from_byte(self, byte):
        unpck = unpack('>HHIIHHHH', byte)
        self.src = unpck[0]
        self.dst = unpck[1]
        self.seq = unpck[2]
        self.ack = unpck[3]
        self.lng = unpck[4] >> 12
        self.flg = self.gen_byte_flag(unpck[4] & 0x1FF)
        self.wndw = unpck[5]
        self.check = unpck[6]
        self.urg = unpck[7]
        if len(byte) > 160:
            unpack_from('', byte, 160)

    def gen_message(self):
        p = pack('!HHIIHHHH', self.src, self.dst, self.seq, self.ack,
                 (self.lng << 12) + self.gen_flag_byte(), self.wndw,
                 self.check, self.urg)
        if self.opt:
            self.gen_lng()
            frmt, opts = self.gen_opt()
            return pack_into(frmt, pack, 160, self.opt)
        self.msg = p
        return self.msg

    def raw_bytes(self):
        if self.msg is None:
            self.gen_message()
        ret = ''
        hx = self.msg.hex()
        for i in range(0, len(hx), 2):
            ret += hx[i:i+2] + ' '
            if (i+2) % 8 == 0 and (i+2) % 16 != 0 and i != 0:
                ret += ' '
            elif (i+2) % 16 == 0 and i != 0:
                ret += '\n'
        return ret

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

    def gen_lng(self):
        self.lng = 5 + int(len(self.opt) / 8) if self.opt else 5

    def size(self):
        return self.gen_lng() * 4

    def gen_opt(self):
        frmt = '!'
        return frmt, opts
