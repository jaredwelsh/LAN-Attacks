import functools
from scapy.all import *

# add multiple clients and victims

class NetAttrs(object):

    def __init__(self, mac=None, ip=None, port=None, name=None):
        self.mac = mac
        self.ip = ip
        self.port = port
        self.name = name

    def __str__(self):
        ret = '\n'
        for k, v in self.__dict__.items():
            if k != 'name':
                ret += "\t\t{} : {}\n".format(k, v)
        return ret[:-1]

    def full(self):
        return self.mac and self.ip and self.port


class Client:
    typ_cmds = {
        -1: [],
        0:  ['both', 'ip', 'intface'],
        1:  ['both', 'all', 'intface'],
        2:  ['both', 'mac', 'intface']
    }

    def __init__(self, attacks=-1):
        self.cli = NetAttrs(name='Client')
        self.vic = NetAttrs(name='Victim')

        self.victims = {}

        self.ethl = None
        self.ipl = None
        self.trnl = {'TCP': None, 'UDP': None}

        self.pcaps = None
        self.intface = None if attacks == -1 else input('Enter Interface: ')

        self.attacks = [attacks]
        self.update(self.typ_cmds[attacks])

    def __str__(self):
        ret = 'Self: \n'
        for k, v in self.__dict__.items():
            if k == 'cli' or k == 'vic':
                ret += "\t{} : {}\n".format(self.rgetattr(k).name, v)
            else:
                ret += "\t{} : {}\n".format(k, v)
        return ret[:-1]

    def add_typ(self, attacks):
        d = []
        if attacks not in self.attacks:
            self.attacks.append(attacks)
            self.update(self.typ_cmds[attacks])

    def rsetattr(self, attr, val):
        pre, _, post = attr.rpartition('.')
        return setattr(self.rgetattr(pre) if pre else self, post, val)

    def rgetattr(self, attr, *args):
        def _getattr(self, attr):
            return getattr(self, attr, *args)
        return functools.reduce(_getattr, [self] + attr.split('.'))

    def set(self, dict):
        for key, value in dict.items():
            # if '.ip' in key and re.match(, value):
            #     pass
            self.rsetattr(key, value)

    def pcap_get_attr(self, ip):
        for packet in self.pcaps:
            if packet[IP].src == ip:
                return packet[Ether].src, packet[TCP].sport

            elif packet[IP].dst == ip:
                return packet[Ether].dst, packet[TCP].dport
        else:
            print("IP address {} not found in pcap".format(ip))
            return None, None

    def set_layer(self, layer, l3=None, typ=None):
        cmd = None
        if not typ:
            cmd = input('Use existing values (y/n/s): ').lower()

            while 's' in cmd:
                print(self)
                cmd = input('Use existing values (y/n/s): ').lower()
        else:
            self.update(self.typ_cmds[typ])

        if cmd and 'n' in cmd:
            cmd_list = ['both']
            if layer >= 1:
                cmd_list.append('mac')
            if layer >= 2:
                cmd_list.append('ip')
            if layer >= 3:
                cmd_list.append('port')
            self.update(cmd_list, True)

        try:
            if not self.cli.mac or not self.vic.mac:
                raise ValueError('MAC')
            elif layer >= 1:
                self.ethl = Ether(src=self.cli.mac, dst=self.vic.mac)

            if not self.cli.ip or not self.vic.ip:
                raise ValueError('IP')
            elif layer >= 2:
                self.ipl = IP(src=self.cli.ip, dst=self.vic.ip)

            if not self.cli.port or not self.vic.port:
                raise ValueError('PORT')
            elif layer >= 3 and l3 == 'TCP':
                self.tranl['TCP'] = TCP(
                    sport=self.cli.port, dport=self.vic.port)
            elif layer >= 3 and l3 == 'UDP':
                self.tranl['UDP'] = UDP(
                    sport=self.cli.port, dport=self.vic.port)

        except ValueError as err:
            print("ERROR You must first set {}".format(err))

    def gen_msg(self):
        if self.ethl and self.ipl and self.tcpl:
            # self.tcp.seq =
            # self.tcp.ack =
            return self.ethl / self.ipl / self.tcpl
        else:
            self.set_layer()

    def update(self, cmd_list, forced=False):
        d = {}
        cmd = cmd_list.pop(0) if cmd_list else ''
        while cmd:
            if 'interface' in cmd and (forced or self.rgetattr('interface') == None):
                d['intface'] = input('Enter Interface: ')
            elif 'pcap' in cmd and (forced or self.rgetattr('pcaps') == None):
                d['pcaps'] = filter(lambda x: x.haslayer(TCP),
                                    rdpcap(input('Enter Pcap path: ')))
            elif cmd in ('both', 'client', 'victim'):
                if 'both' in cmd:
                    na = [('cli', self.cli.ip, 'Client'),
                          ('vic', self.vic.ip, 'Victim')]
                elif 'cli' in cmd:
                    na = [('cli', self.cli.ip, 'Client')]
                elif 'vic' in cmd:
                    na = [('vic', self.vic.ip, 'Victim')]

                cmd = cmd_list.pop(0) if cmd_list else ''
                if 'pcap' in cmd:
                    if (
                        not self.pcaps or
                        'n' in input('Use existing Pcap (y/n): ').lower()
                    ):
                        self.pcaps = filter(
                            lambda x: x.haslayer(TCP),
                            rdpcap(input("Enter Pcap path: ")))

                    d[i[0] + '.mac'], d[i[0] +
                                        '.port'] = self.pcap_get_attr(i[1])

                    if not d[i[0] + '.mac'] or not d[i[0] + '.port']:
                        del d[i[0] + '.mac']
                        del d[i[0] + '.port']

                    cmd = cmd_list.pop(0) if cmd_list else ''
                    continue

                while cmd in ('mac', 'ip', 'port', 'all'):
                    for i in na:
                        if 'all' in cmd:
                            for j in ['mac', 'ip', 'port']:
                                if forced or self.rgetattr(i[0] + '.' + j) == None:
                                    d[i[0] + '.' +
                                        j] = input('Enter {} {}: '.format(i[2], j))
                        else:
                            if forced or self.rgetattr(i[0] + '.' + cmd) == None:
                                d[i[0] + '.' +
                                    cmd] = input('Enter {} {}: '.format(i[2], cmd))
                    cmd = cmd_list.pop(0) if cmd_list else ''

                continue

            cmd = cmd_list.pop(0) if cmd_list else ''

        self.set(d)
