class Victim:

    def __init__(self, mac, ip, port):
        self.ip = ip
        self.mac = mac
        self.port = int(port) if port else self.port = None
