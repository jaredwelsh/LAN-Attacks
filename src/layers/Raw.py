from struct import pack, unpack_from, unpack


class Raw():
    def __init__(self, msg=None):
        self.layer = 'l4'
        self.msg = msg

    def __str__(self):
        ret = 'Raw: \n'
        for k, v in self.__dict__.items():
            if k not in 'layer':
                ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def type(self):
        return 'Raw'

    def build_from_byte(self, byte):
        pass

    def gen_message(self):
        return self.msg if self.msg else b''

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

    def size(self):
        if not self.msg:
            self.gen_message()
        return len(self.msg)
