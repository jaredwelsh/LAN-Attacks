from ast import literal_eval
from scapy.all import *


class NetAttrs:
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
        -1: [],                                     # invalid
        0: ['all', 'ip', 'interface'],              # TCP Reset
        1: ['pcap', 'all', 'pcap', 'interface'],    # TCP Replay
        2: ['all', 'mac', 'interface'],             # Deauth
        3: ['all', 'mac', 'ip', 'interface']        # Arp Poison
    }

    def __init__(self):
        self.victims = {}

        self.pcaps = {}
        self.intface = None

        self.attacks = []

    def __str__(self):
        ret = 'Self: \n'
        for k, v in self.__dict__.items():
            if k == 'victims':
                for k1, v1 in self.victims.items():
                    ret += "\t{} : {}\n".format(k1, v1)
            elif k == 'pcaps':
                ret += "\tpcaps : {}\n".format(', '.join(self.pcaps.keys()))
            else:
                ret += "\t{} : {}\n".format(k, v)
        return ret[:-1]

    def exprt(self, path):
        t = {
            'victims': {},
            'pcaps': [p for p in self.pcaps.keys()],
            'intface': self.intface,
            'attacks': self.attacks
        }
        for k, v in self.victims.items():
            t['victims'][k] = v.__dict__

        with open(path, 'w') as f:
            f.write(str(t))
        print('Export Successful')

    def imprt(self, path):
        with open(path, 'r') as f:
            t = f.read()
        for k, v in literal_eval(t).items():
            if 'victims' in k:
                for k1, v1 in v.items():
                    self.victims[k1] = NetAttrs(mac=v1['mac'],
                                                ip=v1['ip'],
                                                port=v1['port'],
                                                name=v1['name'])

            elif 'pcaps' in k:
                for pcapf in v:
                    self.pcaps[pcapf] = filter(
                        lambda x: x.haslayer(TCP) or x.haslayer(UDP),
                        rdpcap(pcapf))
            else:
                setattr(self, k, v)
        print("Import Successful")

    def remove(self, cmd_list):
        typ = cmd_list.pop(0) if cmd_list else ''
        cmd = cmd_list.pop(0) if cmd_list else ''
        while cmd:
            if 'victim' in typ:
                del self.victims[cmd]
            elif 'pcap' in typ:
                del self.pcaps[cmd]
            cmd = cmd_list.pop(0) if cmd_list else ''

    def run(self, func, src, dst, tcp=False):
        func(self, self.victims[src], self.victims[dst])

    def add_options(self, p, options):
        for k, v in options.items():
            for k1, v1 in v.items():
                setattr(p[k], k1, v1)

    def gen_layers(self, src=None, dst=None, tcp=False):
        l0 = Ether(src=src.mac, dst=dst.mac)
        l1 = IP(src=src.ip, dst=dst.ip)
        l2 = TCP(sport=int(src.port), dport=int(dst.port)) if tcp else UDP(
            sport=src.port, dport=dst.port)
        return l0, l1, l2

    def add_vic(self, names):
        for name in names:
            if name not in self.victims.keys():
                self.victims[name] = NetAttrs(name=name)
            else:
                print('ERROR: Name {} already exists'.format(name))

    def add_typ(self, attacks):
        if len(self.victims.keys()) < 2:
            print('You must have at least 2 victims')
        while len(self.victims.keys()) < 2:
            self.add_vic([input('Enter Victim Name: ')])
        if attacks not in self.attacks:
            self.attacks.append(attacks)
            self.attacks.sort()
            self.update(self.typ_cmds[attacks])

    def pcap_set_attr(self, victim_list, pcap):
        for v in victim_list:
            for packet in pcap:
                if packet.haslayer(IP) and packet[IP].src == v.ip:
                    setattr(v, 'mac', packet[Ether].src)
                    v.port = packet[TCP].sport if packet.haslayer(
                        TCP) else packet[UDP].sport
                    print("IP address {} found".format(v.ip))
                    break

                elif packet.haslayer(IP) and packet[IP].dst == v.ip:
                    setattr(v, 'mac', packet[Ether].dst)
                    v.port = packet[TCP].dport if packet.haslayer(
                        TCP) else packet[UDP].dport
                    print("IP address {} found".format(v.ip))
                    break
            else:
                print("ERROR: IP address {} not found in pcap".format(v.ip))

    def update(self, cmd_list, forced=False):
        if 'interface' in cmd_list:
            cmd = 'interface'
            cmd_list.remove('interface')
        else:
            cmd = cmd_list.pop(0) if cmd_list else ''
        while cmd:
            if 'interface' in cmd and (forced or not self.intface):
                self.intface = input('Enter Interface: ')
            elif 'pcap' in cmd and (forced or not self.pcaps):
                pcapf = cmd_list.pop(0) if ':' in cmd else input(
                    'Enter Pcap path: ')
                if pcapf in self.pcaps.keys():
                    cmd = cmd_list.pop(0) if cmd_list else ''
                    continue
                else:
                    self.pcaps[pcapf] = filter(
                        lambda x: x.haslayer(TCP) or x.haslayer(UDP),
                        rdpcap(pcapf))
            elif cmd in 'all' or cmd in self.victims.keys():
                na = self.victims.values() if 'all' in cmd else [
                    self.victims[cmd]
                ]

                cmd = cmd_list.pop(0) if cmd_list else ''
                if cmd in ('pcap', 'pcap:'):
                    self.update([
                        j
                        for sub in zip([n.name for n in na], ['ip'] * len(na))
                        for j in sub
                    ])

                    if 'pcap:' in cmd:
                        pcapf = cmd_list.pop(0)

                    elif 'pcap' in cmd:
                        pcapf = input("Enter Pcap path: ")

                    if pcapf not in self.pcaps.keys():
                        self.update(['pcap:', pcapf])
                        self.pcaps[pcapf.split('/')[-1]] = {
                            'path': pcapf,
                            'value': filter(
                                lambda x: x.haslayer(TCP) or x.haslayer(UDP),
                                rdpcap(pcapf)
                                )}
                    self.pcap_set_attr(na, self.pcaps[pcapf])

                    cmd = cmd_list.pop(0) if cmd_list else ''
                    continue

                while cmd in ('mac', 'ip', 'port', 'all', 'mac:', 'ip:',
                              'port:'):
                    for v in na:
                        if 'all' in cmd:
                            for j in ['mac', 'ip', 'port']:
                                if forced or not getattr(v, j):
                                    setattr(
                                        v, j,
                                        input('Enter {} {}: '.format(
                                            v.name, j)))
                        else:
                            if ':' in cmd:
                                setattr(v, cmd[:-1], cmd_list.pop(0))
                            elif forced or not getattr(v, cmd):
                                setattr(
                                    v, cmd,
                                    input('Enter {} {}: '.format(v.name, cmd)))

                    cmd = cmd_list.pop(0) if cmd_list else ''
                continue

            cmd = cmd_list.pop(0) if cmd_list else ''
