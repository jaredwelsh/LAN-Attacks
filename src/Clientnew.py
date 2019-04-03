import functools
from ast import literal_eval
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
        0:  ['all', 'ip', 'interface'],
        1:  ['pcap', 'all', 'all', 'interface'],
        2:  ['all', 'mac', 'interface']
    }

    def __init__(self):
        self.victims = {}

        self.pcapf = None
        self.pcaps = None
        self.intface = None

        self.attacks = []

    def __str__(self):
        ret = 'Self: \n'
        for k, v in self.__dict__.items():
            if k == 'victims':
                for k1, v1 in self.victims.items():
                    ret += "\t{} : {}\n".format(k1, v1)
            else:
                ret += "\t{} : {}\n".format(k, v)
        return ret[:-1]

    def exprt(self, path):
        with open(path, 'w') as f:
            f.write({
                'victims': self.victims,
                'pcapf': self.pcapf,
                'intface': self.intface,
                'attacks': self.attacks
            })

    def imprt(self, path):
        with open(path, 'r') as f:
            t = f.read()
        for k, v in literal_eval(t).items():
            setattr(self, k, v)
        self.pcaps = filter(
            lambda x: x.haslayer(TCP) or x.haslayer(UDP),
            rdpcap(self.pcapf))

    def add_vic(self, name):
        self.victims[name] = NetAttrs(name=name)

    def add_typ(self, attacks):
        if len(self.victims.keys()) < 2:
            print('You must have at least 2 victims')
        while len(self.victims.keys()) < 2:
            self.add_vic(input('Enter Victim Name: '))
        if attacks not in self.attacks:
            self.attacks.append(attacks)
            self.update(self.typ_cmds[attacks])

    def pcap_get_attr(self, victim_list):
        for v in victim_list:
            for packet in self.pcaps:
                if packet[IP].src == v.ip:
                    v.mac = packet[Ether].src
                    v.port = packet[TCP].sport if packet.haslayer(TCP) else packet[
                        UDP].sport

                elif packet[IP].dst == v.ip:
                    v.mac = packet[Ether].dst
                    v.port = packet[TCP].dport if packet.haslayer(TCP) else packet[
                        UDP].dport
            else:
                print("IP address {} not found in pcap".format(v.ip))

    def update(self, cmd_list, forced=False):
        cmd = cmd_list.pop(0) if cmd_list else ''
        while cmd:
            if 'interface' in cmd and (forced or not self.intface):
                self.intface = input('Enter Interface: ')
            elif 'pcap' in cmd and (forced or not self.pcaps):
                self.pcapf = input('Enter Pcap path: ')
                self.pcaps = filter(lambda x: x.haslayer(TCP) or x.haslayer(UDP),
                                    rdpcap(self.pcapf))
            elif cmd in 'all' or cmd in self.victims.keys():
                na = self.victims.values() if 'all' in cmd else [
                    self.victims[cmd]]

                cmd = cmd_list.pop(0) if cmd_list else ''
                if 'pcap' in cmd:
                    if (
                        not self.pcaps or
                        'n' in input('Use existing Pcap (y/n): ').lower()
                    ):
                        self.pcapf = input("Enter Pcap path: ")
                        self.pcaps = filter(
                            lambda x: x.haslayer(TCP) or x.haslayer(UDP),
                            rdpcap(self.pcapf))

                    self.pcap_set_attr(na)

                    cmd = cmd_list.pop(0) if cmd_list else ''
                    continue

                while cmd in ('mac', 'ip', 'port', 'all'):
                    for v in na:
                        if 'all' in cmd:
                            for j in ['mac', 'ip', 'port']:
                                if forced or getattr(v, j) == None:
                                    setattr(v, j, input(
                                        'Enter {} {}: '.format(v.name, j)))
                        else:
                            if forced or getattr(v, cmd) == None:
                                setattr(v, cmd, input(
                                    'Enter {} {}: '.format(v.name, cmd)))

                    cmd = cmd_list.pop(0) if cmd_list else ''
                continue

            cmd = cmd_list.pop(0) if cmd_list else ''
