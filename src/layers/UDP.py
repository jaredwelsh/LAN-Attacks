from struct import pack, unpack


class UDP():
    def __init__(self, src=1024, dst=2048, lng=8, check=0, from_bytes=None):
        self.layer = 'l3'
        if from_bytes:
            self.msg = from_bytes
            self.build_from_byte(from_bytes)
        else:
            self.src = src
            self.dst = dst
            self.lng = lng
            self.check = check
            self.msg = None

    def __str__(self):
        ret = 'udp: \n'
        for k, v in self.__dict__.items():
            if k in ('check', 'iden'):
                ret += '\t{}: {}\n'.format(k, hex(v))
            elif k not in ('msg', 'layer'):
                ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def type(self):
        return "UDP"

    def build_from_byte(self, byte):
        unpck = unpack('>HHHH', byte)
        self.src = unpck[0]
        self.dst = unpck[1]
        self.lng = unpck[2]
        self.check = unpck[3]

    def gen_message(self):
        self.msg = pack('!HHHH', self.src, self.dst, self.lng, self.check)
        return self.msg

    def set_lng(self, l4_len):
        self.lng += l4_len

    def set_check(self, p_head, l4):
        self.check = 0
        for part in (p_head, pack('!HHH', self.src, self.dst, self.lng), l4):
            for i in range(0, len(part), 2):
                if (i + 1) < len(part):
                    self.check += part[i] + (part[i + 1] << 8)
                elif (i + 1) == len(part):
                    self.check += part[i]
        self.check = ((self.check + (self.check >> 16)) & 0xffff) ^ 0xffff
        self.check = ((self.check >> 8) & 0xff) | ((self.check << 8) & 0xff00)
        self.check -= self.lng

    def size(self):
        return self.lng

    def raw_bytes(self):
        if self.msg is None:
            self.gen_message()
        ret = ''
        hx = self.msg.hex()
        for i in range(0, len(hx), 2):
            ret += hx[i:i + 2] + ' '
            if (i + 2) % 16 == 0 and (i + 2) % 32 != 0 and i != 0:
                ret += ' '
            elif (i + 2) % 32 == 0 and i != 0:
                ret += '\n'
        return ret
