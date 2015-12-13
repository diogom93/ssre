class Packet:
    def __init__(self, msg, mac, iv):
        self.msg = msg
        self.mac = mac
        self.iv = iv
        self.attributes = {}

    def add_attribute(self, object, id):
        self.attributes[ str(id) ] = object

    def remove_attribute(self, id):
        self.attributes.pop(str(id), None)

    def get_attribute(self, id):
        return self.attributes[str(id)]
