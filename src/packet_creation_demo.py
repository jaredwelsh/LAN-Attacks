#!/usr/bin/env python3
import Packet
from layers import Ether, IPv4, UDP, TCP, Raw

# check endianess for IPv4 and tcp/udp checksum
def main():
    eth = Ether.Ether(src='f0:18:98:1c:cd:7c',
                      dst='00:00:0c:07:ac:00',
                      typ='IPv4')
    ip = IPv4.IPv4(iden=0x0,
                   ttl=64,
                   frag=0x4000,
                   src='10.104.25.69',
                   dst='34.206.172.86')
    tcp = TCP.TCP(dst=443,
                  src=57883,
                  seq=792649593,
                  ack=1481873834,
                  flg='A',
                  wndw=2047,
                  opt=[(1,), (1,), (8, 10, 356789231, 1064150332)])
    pack = Packet.Packet(l1=eth, l2=ip, l3=tcp)
    pack2 = Packet.Packet(from_bytes=bytearray.fromhex('00000c07ac00f018981ccd7c0800450000340000400040060f8e0a68194522c5e4c4e1fd01bb791c683bfd20b0eb801007ff4f0a00000101080a155c4f4a00a41c16'))
    print(pack2)
    print(pack2.raw_bytes())


if __name__ == '__main__':
    main()
