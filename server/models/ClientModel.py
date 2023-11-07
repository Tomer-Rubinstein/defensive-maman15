
class Client:
    def __init__(self, user_id, name, public_key, last_seen, aes_key):
        self.id = user_id
        self.name = name
        self.public_key = public_key
        self.last_seen = last_seen
        self.aes_key = aes_key
