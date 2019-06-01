#!/usr/bin/env python3
import Packet
from layers import Ether, IPv4, UDP, TCP, Raw


def main():
    eth = Ether.Ether(src='f0:18:98:1c:cd:7c',
                      dst='00:00:0c:07:ac:00',
                      typ='IPv4')
    ip = IPv4.IPv4(iden=0x6fe7,
                   ttl=64,
                   frag=0x0,
                   src='10.104.17.220',
                   dst='34.199.181.167')
    tcp = TCP.TCP(dst=443,
                  src=63688,
                  seq=2019708874,
                  ack=3234605178,
                  flg='A',
                  wndw=2048)
    pack = Packet.Packet(l1=eth, l2=ip, l3=tcp)
    pack2 = Packet.Packet(from_bytes=bytes.fromhex('00000c07ac00f018981ccd7c0800450000286fe70000400616370a6811dc22c7b5a7f8c801bb78624fcac0cc287a50100800072b0000'))
    print(pack)
    print(pack2)
    print(pack.raw_bytes())
    print(pack2.raw_bytes())


if __name__ == '__main__':
    main()
