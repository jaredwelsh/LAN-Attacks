class Ether():
    EtherType = {'ipv4': b'0800', 'arp': b'0806', 'ipv6': b'86dd'}

    def __init__(self,
                 src='FF:FF:FF:FF:FF:FF',
                 dst='00:00:00:00:00:00',
                 typ='ipv4'):
        self.src = src
        self.dst = dst
        self.typ = EtherType[typ]

    def gen_message(self):
        return self.to_bytes(self.dst) + self.to_bytes(self.src) + self.typ

    def to_bytes(self, addr):
        return b''.join([a.encode() for a in addr.split(':')])
