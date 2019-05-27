from layers import Ether, IPv4, UDP, TCP, Raw
from Client import NetAttrs
from sys import exit


class Packet():
    def __init__(self, l1=None, l2=None, l3=None, l4=Raw.Raw(msg=b'')):
        self.msg = None

        self.l1 = l1
        self.l2 = l2
        self.l3 = l3
        self.l4 = l4

        self.build()

    def __str__(self):
        ret = ''
        ret += self.l1.__str__() + '\n' if self.l1 else 'L1: \n\tNone\n'
        ret += self.l2.__str__() + '\n' if self.l2 else 'L2: \n\tNone\n'
        ret += self.l3.__str__() + '\n' if self.l3 else 'L3: \n\tNone\n'
        ret += self.l4.__str__() if self.l4 else 'L4: \n\tNone'
        return ret

    def build(self):
        for level, layer in enumerate([self.l1, self.l2, self.l3, self.l4]):
            if layer:
                self.autofill(layer)
            else:
                print('layer {} is None'.format(level))
        self.msg = self.l1.msg + self.l2.msg + self.l3.msg + self.l4.msg

    def raw_bytes(self):
        if self.msg is None:
            self.build()
        ret = ''
        hx = self.msg.hex()
        for i in range(0, len(hx), 2):
            ret += hx[i:i + 2] + ' '
            if (i + 2) % 16 == 0 and (i + 2) % 32 != 0 and i != 0:
                ret += ' '
            elif (i + 2) % 32 == 0 and i != 0:
                ret += '\n'
        return ret

    def types(self):
        types = []
        for layer in (self.l1, self.l2, self.l3, self.l4):
            if layer:
                types.append(layer.type())
        return types

    def autofill(self, layer):
        if layer.type() == 'Ether':
            if self.l2 is None:
                print("Need Layer 2 to build Ethernet header")
            else:
                layer.set_typ(self.l2.type())
            layer.gen_message()

        elif layer.type() == 'IPv4':
            if any([x is None for x in (self.l1, self.l3)]):
                print('Need Layer 1 and 3 to build IP header')
            else:
                layer.set_tlen(self.l3.size() + self.l4.size())
                layer.set_proto(self.l3.type())
                layer.gen_message()

        elif layer.type() == 'ARP':
            pass

        elif layer.type() == 'TCP':
            if not self.l4:
                self.l4 = Raw.Raw(msg=b'')
            p_head = self.l2.psuedo_header()
            layer.gen_message()
            layer.set_check(p_head, self.l4.msg)

        elif layer.type() == 'UDP':
            if not self.l4:
                self.l4 = Raw.Raw(msg=b'')
            p_head = self.l2.psuedo_header()
            layer.set_lng(self.l4.size())
            layer.set_check(p_head, self.l4.msg)
            layer.gen_message()
