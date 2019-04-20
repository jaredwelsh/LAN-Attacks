from struct import pack
class Ether():
    EtherType = {'ipv4': 2048, 'arp': 2054, 'ipv6': 34525}

    def __init__(self,
                 src='FF:FF:FF:FF:FF:FF',
                 dst='00:00:00:00:00:00',
                 typ='ipv4'):
        self.src = src
        self.dst = dst
        self.typ = self.EtherType[typ]

    def __str__(self):
        ret = 'Ether: \n'
        for k, v in self.__dict__.items():
            ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def gen_message(self):
        return pack('!6s6sH', self.addr_to_bytes(self.dst),
                    self.addr_to_bytes(self.src), self.typ)

    def addr_to_bytes(self, addr):
        return bytes.fromhex(addr.replace(":", ""))
