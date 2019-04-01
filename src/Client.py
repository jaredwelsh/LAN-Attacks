import functools


class NetAttrs(object):

    def __init__(self, mac, ip, port, name):
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
        self.cli = NetAttrs(None, None, None, 'Client')
        self.vic = NetAttrs(None, None, None, 'Victim')

        self.ethl = None
        self.ipl = None
        self.tcpl = None

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

    def set_layers(self):
        if self.vic.full and self.cli.full:
            self.ethl = Ether(src=self.cli.mac, dst=self.vic.mac)
            self.ipl = IP(src=self.cli.ip, dst=self.vic.ip)
            self.tcpl = TCP(sport=self.cli.port, dport=self.vic.port)
        else:
            print("You must first set all fields")

    def gen_msg(self):
        if self.ethl and self.ipl and self.tcpl:
            # self.tcp.seq =
            # self.tcp.ack =
            return self.ethl / self.ipl / self.tcpl
        else:
            self.set_layers()

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
