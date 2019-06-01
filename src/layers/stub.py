from struct import pack, unpack_from, unpack


class stub():
    def __init__(self, src=None, dst=None, from_bytes=None):
        if from_bytes:
            self.msg = from_bytes
            self.build_from_byte(from_bytes)
        else:
            self.src = src
            self.dst = dst
            self.msg = None

    def __str__(self):
        ret = 'stub: \n'
        for k, v in self.__dict__.items():
            if k not in 'msg':
                ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def type(self):
        return 'stub'

    def build_from_byte(self, byte):
        unpck = unpack('>HH', byte)
        self.src = unpck[0]
        self.dst = unpck[1]

    def gen_message(self):
        self.msg = pack('>HH', self.src, self.dst)
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

    def size(self):
        return 14
