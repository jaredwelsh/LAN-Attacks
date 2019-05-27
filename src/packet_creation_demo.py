#!/usr/bin/env python3
import Packet
from layers import Ether, IPv4, UDP, TCP, Raw


def main():
    eth = Ether.Ether(src='f0:18:98:1c:cd:7c',
                      dst='58:ef:68:6b:79:da',
                      typ='IPv4')
    ip = IPv4.IPv4(iden=0x0,
                   ttl=64,
                   frag=0x4000,
                   dst='52.109.12.110',
                   src='192.168.1.24')
    tcp = TCP.TCP(src=49324,
                  dst=443,
                  seq=3584908317,
                  ack=3978517886,
                  flg='A',
                  wndw=2048,
                  opt=[(1,), (1,), (8, 10, 284746407, 2045839042), (1,), (1,),
                       (5, 10, 3978517841, 3978517886)])
    pack = Packet.Packet(l1=eth, l2=ip, l3=tcp)
    print(pack)
    print(pack.raw_bytes())


if __name__ == '__main__':
    main()
