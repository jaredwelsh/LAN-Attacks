from struct import pack, unpack


EtherType = {'IPv4': 2048, 'ARP': 2054, 'IPv6': 34525}


class Ether():

    def __init__(self,
                 src='FF:FF:FF:FF:FF:FF',
                 dst='00:00:00:00:00:00',
                 typ='IPv4',
                 from_bytes=None):
        if from_bytes:
            self.msg = from_bytes
            self.build_from_byte(from_bytes)
        else:
            self.src = src
            self.dst = dst
            self.typ = EtherType[typ]
            self.msg = None

    def __str__(self):
        ret = 'Ether: \n'
        for k, v in self.__dict__.items():
            if k not in ('msg', 'layer'):
                ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def type(self):
        return "Ether"

    def build_from_byte(self, byte):
        s = byte.hex()
        self.src = ':'.join([s[i:i+2] for i in range(12, 24, 2)])
        self.dst = ':'.join([s[i:i+2] for i in range(0, 12, 2)])
        self.typ = unpack(">H", byte[12:])[0]

    def gen_message(self):
        self.msg = pack('!6s6sH', self.addr_to_bytes(self.dst),
                        self.addr_to_bytes(self.src), self.typ)
        return self.msg

    def set_typ(self, typ):
        self.typ = EtherType[typ]

    def size(self):
        return 14

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

    def addr_to_bytes(self, addr):
        return bytes.fromhex(addr.replace(":", ""))
