from layers import Ether, IPv4, UDP, TCP
from Client import NetAttrs
from sys import exit


class Packet():

    AutoFillTypes = {
                'Ethernet': autofill_Ethernet,
                'IPv4': autofill_IPv4,
                'ARP': autofill_ARP,
                'TCP': autofill_TCP,
                'UDP': autofill_UDP
                }

    def __init__(self, l1=None, l2=None, l3=None, l4=None):
        self.msg = None

        self.l1 = l1
        self.l2 = l2
        self.l3 = l3
        self.l4 = l4

        self.build()

    def __str__(self):
        ret = ''
        ret += self.l1.__str__() if self.l1 else 'L1: \n\tNone\n'
        ret += self.l2.__str__() if self.l2 else 'L2: \n\tNone\n'
        ret += self.l3.__str__() if self.l3 else 'L3: \n\tNone\n'
        ret += self.l4.__str__() if self.l4 else 'L4: \n\tNone'
        return ret

    def build(self):
        for level, layer in enumerate([self.l1, self.l2, self.l3, self.l4]):
            if layer:
                AutoFillTypes[layer.type()]()
            else:
                print('ERROR layer {} is None'.format(level))

    def dummy(self):
        self.l1 = Ether.Ether()
        self.l2 = IPv4.IPv4()
        self.l3 = TCP.TCP()
        self.update(self.l1)

    def raw_bytes(self):
        if self.msg is None:
            self.gen_message()
        ret = ''
        hx = self.msg.hex()
        for i in range(0, len(hx), 2):
            ret += hx[i:i + 2] + ' '
            if (i + 2) % 8 == 0 and (i + 2) % 16 != 0 and i != 0:
                ret += ' '
            elif (i + 2) % 16 == 0 and i != 0:
                ret += '\n'
        return ret

    def types(self):
        types = []

        if self.l1:
            types.append(self.l1.type())
        if self.l2:
            types.append(self.l2.type())
        if self.l3:
            types.append(self.l3.type())
        if self.l4:
            types.append(self.l4.type())

        return types

    def autofill_Ethernet(self):
        if self.l2 is None:
            print("Need Layer 2 to build Ethernet header")
        else:
            self.l1.set_typ(self.l2.type())
            self.l1.gen_message()

    def autofill_IPv4(self, l2):
        if any([x is None for x in (self.l1, self.l3)]):
            print('Need Layer 1 and 3 to build IP header')
        else:
            self.l2.set_tlen(self.l1.size() + self.l3.size() + self.l4.size())
            self.gen_message()

    def autofill_ARP(self):
        pass

    def autofill_TCP(self, l3):
        pass

    def autofill_UDP(self, l3):
        if not self.l4:
            self.l4 = b''
        p_head, tlen = self.l2.psuedo_header()
        self.l3.set_lng(len(self.l4))
        self.l3.set_check(p_head, self.t4, tlen)
        self.l3.gen_message()
