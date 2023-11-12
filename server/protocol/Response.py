import struct

SERVER_VERSION = 2


class Response:
    def __init__(self, code, payload_size, payload):
        self.code = code
        self.payload_size = payload_size
        self.payload = payload


    @staticmethod
    def pack_uuid(uuid_hex) -> bytes:
        uuid_int = int(uuid_hex, 16)
        max_int64 = 0xFFFFFFFFFFFFFFFF

        return struct.pack("<QQ", (uuid_int & max_int64), (uuid_int >> 64))


    @staticmethod
    def unpack_uuid(uuid_bytes):
        if uuid_bytes == bytes(16) or uuid_bytes == b'':
            return bytes(16).decode()

        a, b = struct.unpack("<QQ", uuid_bytes)
        unpacked = (b << 64) | a
        return f'{unpacked:x}' # convert to hex string without '0x' prefix


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
# NOTE: no payload for response codes 2107, 2101.


def payload_resp_code_2100(client_id: str):
    return Response.pack_uuid(client_id)


def payload_resp_code_2102(client_id: str, encrypted_aes_key: bytes):
    format_str = f"<16s {len(encrypted_aes_key)}s"
    client_id = Response.pack_uuid(client_id)
    return struct.pack(format_str, client_id, encrypted_aes_key)


def payload_resp_code_2103(client_id: str, content_size: int, filename: bytes, cksum: int):
    # content_size - size of input file after AES encryption
    format_str = f"<16s I 255s I"
    client_id = Response.pack_uuid(client_id)
    return struct.pack(format_str, client_id, content_size, filename, cksum)


def payload_resp_code_2104(client_id: str):
    return payload_resp_code_2100(client_id)


def payload_resp_code_2105(client_id: str, encrypted_aes_key: bytes):
    return payload_resp_code_2102(client_id, encrypted_aes_key)


def payload_resp_code_2106(client_id: str):
    return payload_resp_code_2100(client_id)
