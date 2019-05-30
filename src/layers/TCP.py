from struct import pack, pack_into, unpack, unpack_from


class TCP():

    FlagType = {'F': 0x01, 'S': 0x02, 'P': 0x08, 'A': 0x10, 'U': 0x20,
                'E': 0x40, 'C': 0x80}

    def __init__(self,
                 src=1024,
                 dst=2048,
                 seq=0,
                 ack=1,
                 lng=5,
                 flg='',
                 wndw=256,
                 check=0,
                 urg=0,
                 opt=None,
                 from_bytes=None):
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
            self.optval = None
            self.msg = None
            if self.opt:
                self.gen_opt()

    def __str__(self):
        ret = 'tcp: \n'
        for k, v in self.__dict__.items():
            if k in ('check', 'iden'):
                ret += '\t{}: {}\n'.format(k, hex(v))
            elif k not in ('msg', 'layer', 'optval'):
                ret += '\t{}: {}\n'.format(k, v)
        return ret[:-1]

    def type(self):
        return "TCP"

    def build_from_byte(self, byte):
        unpck = unpack('>HHIIHHHH', byte[:20])
        self.src = unpck[0]
        self.dst = unpck[1]
        self.seq = unpck[2]
        self.ack = unpck[3]
        self.lng = unpck[4] >> 12
        self.flg = self.gen_byte_flag(unpck[4] & 0x1FF)
        self.wndw = unpck[5]
        self.check = unpck[6]
        self.urg = unpck[7]
        if self.lng > 5:
            i = 20
            while (i < self.lng * 4):
                i += 1

    def gen_message(self):
        p = pack('!HHIIHHHH', self.src, self.dst, self.seq, self.ack,
                 (self.lng << 12) + self.gen_flag_byte(), self.wndw,
                 self.check, self.urg)
        if self.opt:
            self.gen_opt()
            p += self.optval
        self.msg = p
        return self.msg

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

    def gen_opt(self):
        frmt = '!'
        optlist = []
        for opt in self.opt:
            if opt[0] == 0:
                frmt += 'B'
                optlist.append(0)
            elif opt[0] == 1:
                frmt += 'B'
                optlist.append(1)
            elif opt[0] == 2:
                frmt += 'BBH'
                optlist += [*opt]
            elif opt[0] == 3:
                frmt += 'BBB'
                optlist += [*opt]
            elif opt[0] == 4:
                frmt += 'BB'
                optlist += [*opt]
            elif opt[0] == 5:
                frmt += 'BBII'
                optlist += [*opt]
            elif opt[0] == 8:
                frmt += 'BBII'
                optlist += [*opt]
            else:
                print('Invalid Option-Kind value')
        self.optval = pack(frmt, *optlist)
        self.gen_lng()

    def gen_lng(self):
        self.lng = 5 + int(len(self.optval) / 4) if self.opt else 5

    def set_check(self, p_head, l4):
        self.check = 0
        for part in (p_head, self.msg, l4):
            for i in range(0, len(part), 2):
                if (i + 1) < len(part):
                    self.check += part[i] + (part[i + 1] << 8)
                elif (i + 1) == len(part):
                    self.check += part[i]
        self.check = ((self.check + (self.check >> 16)) & 0xffff) ^ 0xffff
        self.check = ((self.check >> 8) & 0xff) | ((self.check << 8) & 0xff00)
        self.check -= self.lng * 4
        self.msg = bytearray(self.msg)
        self.msg[16] = self.check >> 8
        self.msg[17] = self.check & 0xff
        self.msg = bytes(self.msg)

    def size(self):
        return self.lng * 4
