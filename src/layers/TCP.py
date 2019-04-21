from struct import pack, unpack


class TCP():

    FIN = 0x01
    SYN = 0x02
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self):
        pass

