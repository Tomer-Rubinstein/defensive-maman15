import sqlite3
import string
import random
from datetime import datetime
from collections import defaultdict

import uuid
import struct

class Database:
    def __init__(self, db_filename):
        self.conn = sqlite3.connect(db_filename)

        def dict_factory(cursor, row):
            doc = {}
            for i, col in enumerate(cursor.description):
                doc[col[0]] = row[i]
            return doc

        self.conn.row_factory = dict_factory
        self.cur = self.conn.cursor()


    def load_clients_list(self) -> list:
        res = self.cur.execute("SELECT * FROM clients")
        return res.fetchall()


    def load_files_list(self) -> list:
        res = self.cur.execute("SELECT * FROM files")
        return res.fetchall()


    # import uuid
    # import struct

    # uuid = uuid.uuid4()

    # max_int64 = 0xFFFFFFFFFFFFFFFF
    # packed = struct.pack("<QQ", uuid.int & max_int64, (uuid.int >> 64))
    # # unpack
    # a, b = struct.unpack("<QQ", packed)
    # unpacked = (b<<64)|a


    def init_tables(self):
        """
        creates empty tables "clients" and "files" if they do not exist
        and loads those tables to RAM, whether they exist or not.
        """
        # Create clients table
        self.cur.execute("""
            CREATE TABLE if not exists clients (
                uid TEXT,
                name TEXT,
                publicKey BLOB,
                lastSeen TEXT,
                AESKey BLOB,
                PRIMARY KEY(UID)
            )
        """)

        # Create files table
        self.cur.execute("""
            CREATE TABLE if not exists files (
                uid TEXT,
                filename TEXT,
                path TEXT,
                verified INTEGER
            )
        """)

        # load clients & files tables from database to RAM
        clients_entries = self.load_clients_list()
        files_entries = self.load_files_list()

        self.client_names = defaultdict(None, {doc["name"]: doc["uid"] for doc in clients_entries})
        self.clients = defaultdict(None, {doc["uid"]: doc for doc in clients_entries})
        self.files = defaultdict(None, {doc["uid"]+"/"+doc["filename"]: doc for doc in files_entries})

        print("### self.clients: ####\n", self.clients)


    def create_client_dict(self, uid, name, publicKey, lastSeen, AESKey):
        return {
            "uid": uid,
            "name": name,
            "publicKey": publicKey,
            "lastSeen": lastSeen,
            "AESKey": AESKey
        }
        

    def create_file_dict(self, uid, filename, path, verified):
        return {
            "uid": uid,
            "filename": filename,
            "path": path,
            "verified": verified
        }


    def get_client_by_name(self, name) -> tuple:
        """
        :param name: client's name
        :return: tuple of user row in clients table
        """
        client_id = self.client_names.get(name)
        client_entry = self.clients.get(client_id)

        return client_entry
        # res = self.cur.execute("SELECT * FROM clients WHERE name=?", (name,))
        # return res.fetchone()
    

    def get_client_by_id(self, client_id) -> tuple:
        print("self.clients:", self.clients)
        client_entry = self.clients.get(client_id)
        return client_entry

        # res = self.cur.execute("SELECT * FROM clients WHERE uid=?", (client_id,))
        # return res.fetchone()


    def add_new_client(self, name) -> bool:
        """
        :param name: client name
        :param publicKey: used to encrypt AES private key
        :param lastSeen: last timestamp user made a request
        :param aesKey: used to encrypt files
        :return: New UID, if user does not exist in "clients" table, o.w. None.
        """
        if self.get_client_by_name(name):
            # user by that name already registered
            return None

        uid = uuid.uuid4() # .hex
        print("new uid int:", uid.int)
        uid = uid.hex 



        # update the real database directly
        self.cur.execute("""
            INSERT INTO clients VALUES (
                ?,
                ?,
                ?,
                ?,
                ?
            )
        """, (uid, name, None, None, None))
        self.conn.commit()

        # update the "RAM database"
        self.client_names[name] = uid
        self.clients[uid] = self.create_client_dict(uid, name, None, None, None)

        return uid


    def set_public_key(self, name, public_key):
        """
        :param name: username
        :param public_key: public key of RSA pair
        :return: user id on successful update, None o.w.
        """
        user = self.get_client_by_name(name)
        if not user:
            return None # user by name(param) does not exist

        self.cur.execute("""
            UPDATE clients
            SET publicKey = ?
            WHERE name = ?
        """, (public_key, name))
        self.conn.commit()

        self.clients[user["uid"]]["publicKey"] = public_key

        return user["uid"]


    def set_aes_key(self, aes_key, client_id):
        user = self.get_client_by_id(client_id)
        if not user:
            return False
        
        self.cur.execute("""
            UPDATE clients
            SET AESKey = ?
            WHERE uid = ?
        """, (aes_key, client_id))
        self.conn.commit()

        self.clients[user["uid"]]["AESKey"] = aes_key

        return True


    def update_last_seen(self, client_id):
        user = self.get_client_by_id(client_id)
        if not user:
            return False

        now = datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")

        self.cur.execute("""
            UPDATE clients
            SET lastSeen = ?
            WHERE uid = ?
        """, (current_time, client_id))

        self.clients[user["uid"]]["lastSeen"] = current_time

        self.conn.commit()
        return True


    def set_file_verified(self, client_id, filename, verified):
        if self.get_client_by_id(client_id) == None:
            return False

        self.cur.execute("""
            UPDATE files
            SET verified = ?
            WHERE uid = ? AND filename = ?
        """, (int(verified), client_id, filename))
        self.conn.commit()

        file_key = client_id+"/"+filename
        self.files[file_key]["verified"] = int(verified)

        return True


    def add_new_file(self, client_id, filename, pathname, verified: bool):
        self.cur.execute("""
            INSERT INTO files VALUES (
                ?,
                ?,
                ?,
                ?
            )
        """, (client_id, filename, pathname, int(verified)))
        self.conn.commit()

        new_file_key = client_id+"/"+filename
        self.files[new_file_key] = self.create_file_dict(client_id, filename, pathname, int(verified))


# # [DEBUG]
# if __name__ == "__main__":
#     db = Database("defensive.db")
#     db.init_tables()
#     # print(db.add_new_client("test", "publickeysmth", "today", "aes_key"))
#     res = db.add_new_client(16*2)
#     print()
#     print(res)
#     print(int(res,16))
