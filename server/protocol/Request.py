import socket
import os

import Crypto
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

from .Response import *
from cksum import memcrc
from DatabaseUtils import Database


class Request:
    def __init__(self, sock: socket.socket, db: Database):
        self.sock = sock
        self.db = db


    @staticmethod
    def bytes_to_int(bytestring):
        return int.from_bytes(bytestring, byteorder="little", signed=False)


    @staticmethod
    def extract_filename(filename):
        """
        extract actual filename from given user input from his relative
        path to the file (either '\' or '/' used).
        assumes no combination of '\' and '/'.

        :param filename: relative path to file in user's perspective
        :return: actual filename from relative path.
        """
        win_style_extract = filename.split("/")[-1]
        unix_style_extract = filename.split("\\")[-1]
        
        if win_style_extract == filename: # no "\" are present
            return unix_style_extract
        return win_style_extract # no "/" are present


    def recv_str_with_null_term(self, byte_count):
        """
        [NOTE] this method clears <byte_count> bytes from the socket's buffer

        :param byte_count: maximum number of bytes expected to receive
        :return: bytestring from socket up until first null terminator
        """
        data = b''
        for _ in range(byte_count):
            c = self.sock.recv(1)
            if c != b'\x00':
                data += c
        
        return data


    def read_header(self):
        # read constant header bytes, according to the protocol
        self.client_id = self.sock.recv(16)
        self.client_version = self.bytes_to_int(self.sock.recv(1))
        self.opcode = self.bytes_to_int(self.sock.recv(2))
        self.payload_size = self.bytes_to_int(self.sock.recv(4))

        print("got header:")
        print(f"\tclient_id = {self.client_id}")
        print(f"\tclient_version = {self.client_version}")
        print(f"\topcode = {self.opcode}")
        print(f"\tpayload_size = {self.payload_size}")

        self.client_id = Response.unpack_uuid(self.client_id) # convert client_id to hex string from 16 bytes

        try:
            # bytes(16).decode() is returned from Response.unpack_uuid()
            # if given uuid is None => don't try to convert None to hex.
            if self.client_id != bytes(16).decode():
                int(self.client_id, 16)
        except ValueError:
            print("[ERROR] Invalid client_id, not an hex value!", self.client_id)
            return False

        return True


    def register_user(self, name):
        new_uid = self.db.add_new_client(name)
        print("New generated UUID: ", new_uid)
        if not new_uid:
            # user by that name already exists
            return Response(2101, 0, None)

        payload = payload_resp_code_2100(new_uid)
        return Response(2100, 16, payload)


    def set_public_key(self, name, public_key):
        uid = self.db.set_public_key(name, public_key)
        if not uid:
            # user by name(param) does not exist
            return Response(2107, 0, None)

        # generate AES key
        aes_key = Crypto.Random.get_random_bytes(16)
        if not self.db.set_aes_key(aes_key, uid):
            print(f"[ERROR] user by id {uid} does not exist!")

        # encrypt key with RSA by public_key
        rsa_public_key = RSA.importKey(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # send response to client
        payload = payload_resp_code_2102(uid, encrypted_aes_key)
        return Response(2102, len(payload), payload)


    def save_file(self, client_id, filename, encrypted_filecontent):
        # sanitize relative path from filename
        filename = Request.extract_filename(filename)

        # get client_id aes key
        client = self.db.get_client_by_id(client_id)
        if not client:
            return Response(2107, 0, None)

        aes_key = client["AESKey"]

        # decrypt filecontent with aes key
        iv = 16 * b'\x00'
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        filecontent_bytes = aes_cipher.decrypt(encrypted_filecontent)
        filecontent_bytes = unpad(filecontent_bytes, 16)

        # save in disk as <filename>
        pathname = f"{self.client_id}"
        os.makedirs(pathname, exist_ok=True)
        with open(pathname+"\\"+filename, "wb") as file:
            file.write(filecontent_bytes)
        
        # save file record in db
        self.db.add_new_file(self.client_id, filename, pathname, False)

        # calculate checksum
        checksum = memcrc(filecontent_bytes)

        payload = payload_resp_code_2103(client_id, len(encrypted_filecontent), filename.encode(), checksum)
        return Response(2103, 16+4+255+4, payload)


    def relogin_user(self, username):
        user = self.db.get_client_by_name(username)
        if not user or not user["publicKey"]:
            return Response(2106, 16, payload_resp_code_2106(self.client_id))

        # generate new AES key
        new_aes_key = Crypto.Random.get_random_bytes(16)

        # update AES key in client entry
        self.db.set_aes_key(new_aes_key, user["uid"])

        # encrypt with publickey of database
        rsa_public_key = RSA.importKey(user["publicKey"])
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(new_aes_key)

        # send success Response(2105, client_id, encrypted_aes_key)
        payload = payload_resp_code_2105(self.client_id, encrypted_aes_key)
        return Response(2105, len(payload), payload)


    def handle_request(self):
        # code 2107 in this context means invalid opcode.
        resp = Response(code=2107, payload_size=0, payload=None)
        print("Got request code:", self.opcode)

        if self.opcode == 1025:
            # registration request
            # payload = name[255 bytes]
            name = self.recv_str_with_null_term(255).decode()
            resp = self.register_user(name)
        elif self.opcode == 1026:
            # send public key of user request
            # payload = name[255 bytes] + public_key[160 bytes]
            name = self.recv_str_with_null_term(255).decode()
            # public key is exactly 160 bytes, can include b'\x00'.
            public_key = self.sock.recv(160)
            resp = self.set_public_key(name, public_key)
        elif self.opcode == 1027:
            # re-login request
            # payload = name[255 bytes]
            name = self.recv_str_with_null_term(255).decode()
            resp = self.relogin_user(name)
        elif self.opcode == 1028:
            # upload file request
            # payload = content_size[4 bytes] + filename[255 bytes] + content[<content_size> bytes]
            content_size = self.bytes_to_int(self.sock.recv(4))
            filename = self.recv_str_with_null_term(255).decode()
            filecontent = self.sock.recv(content_size) # NOTE: is encrypted by symmetric key
            resp = self.save_file(self.client_id, filename, filecontent)
        elif self.opcode == 1029:
            # valid CRC request
            # payload = filename[255 bytes]
            filename = self.recv_str_with_null_term(255).decode()

            # update db row to verified=True
            self.db.set_file_verified(self.client_id, filename, True)

            payload = payload_resp_code_2104(self.client_id.encode())
            resp = Response(2104, 16, payload)
        elif self.opcode == 1030:
            # invalid CRC, send again request
            # payload = filename[255 bytes]
            filename = self.recv_str_with_null_term(255).decode()
            payload = payload_resp_code_2104(self.client_id.encode())
            resp = Response(2104, 16, payload)
        elif self.opcode == 1031:
            # invalid CRC 4th time, give up request
            # payload = filename[255 bytes]
            filename = self.recv_str_with_null_term(255).decode()
            payload = payload_resp_code_2104(self.client_id.encode())
            
            # mark file in db as not verified
            self.db.set_file_verified(self.client_id, filename, False)
            resp = Response(2104, 16, payload)

        # update last seen
        self.db.update_last_seen(self.client_id)

        # send response to client
        print("Sending response:")
        print("\tcode:", resp.code)
        print("\tpayload_size:", resp.payload_size)
        print("\tpayload:", resp.payload)
        resp = resp.pack()
        self.sock.sendall(resp)
