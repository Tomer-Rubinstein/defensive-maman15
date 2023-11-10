import struct

SERVER_VERSION = 2

class Response:
    def __init__(self, code, payload_size, payload):
        self.code = code
        self.payload_size = payload_size
        self.payload = payload


    def pack(self):
        header = struct.pack("<BHI", SERVER_VERSION, self.code, self.payload_size)
        payload = self.payload
        
        if self.code == 2107 or self.code == 2101:
            return header

        return header+payload


# -----------------------------------------------------
# the following functions are used to generate payloads
# for the different kinds of possible responses
# -----------------------------------------------------

def payload_resp_code_2100(client_id: bytes):
    return struct.pack("<16s", client_id)


def payload_resp_code_2101():
    ...


def payload_resp_code_2102(client_id: bytes, encrypted_aes_key: bytes):
    format_str = f"<16s {len(encrypted_aes_key)}s"
    return struct.pack(format_str, client_id, encrypted_aes_key)


def payload_resp_code_2103(client_id: bytes, content_size: int, filename: bytes, cksum: int):
    # content_size - size of input file after AES encryption
    format_str = f"<16s I 255s I"
    return struct.pack(format_str, client_id, content_size, filename, cksum)


def payload_resp_code_2104(client_id: bytes):
    return payload_resp_code_2100(client_id)


def payload_resp_code_2105(client_id: bytes, encrypted_aes_key: bytes):
    return payload_resp_code_2102(client_id, encrypted_aes_key)


def payload_resp_code_2106(client_id: bytes):
    return payload_resp_code_2100(client_id)


def payload_resp_code_2107():
    ...



# DEBUG
if __name__ == "__main__":
    print(payload_resp_code_2103("hsQU2s3c8DNsis1I".encode(), 65, "lol.txt".encode(), 6565))
