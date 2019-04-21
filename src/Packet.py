from layers import Ether, IPv4


class Packet():

    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.msg = None

    def gen_message(self):
        self.l0 = Ether.Ether(src=self.src.mac, dst=self.dst.mac)
        self.l1 = IPv4.IPv4(src=self.src.ip, dst=self.dst.ip)
        return self.l0 + self.l1

    def dummy_gen(self):
        self.l0 = Ether.Ether(dst="08:00:27:c6:d8:cf", src="08:00:27:7d:9b:7e")
        self.l1 = IPv4.IPv4(src="192.168.56.3", dst="192.168.56.5")
        return self.l0.gen_message() + self.l1.gen_message()
