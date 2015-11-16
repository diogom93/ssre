class Packet:
    def __init__(self, msg, mac, iv):
        self.msg = msg
        self.mac = mac
        self.iv = iv
