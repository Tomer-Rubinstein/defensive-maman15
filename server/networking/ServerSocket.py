import socket
from protocol import Request
from DatabaseUtils import Database
from protocol import Response

class ServerSocket:
    def __init__(self, port, host):
        self.host = host
        self.port = port


    def init_socket(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server listening on port: {self.port}..")


    def handle_client(self, client_socket: socket.socket, db: Database):
        req = Request(client_socket, db)
        if not req.read_header():
            resp = Response(2107, 0, None).pack() # error response
            client_socket.sendall(resp)
            return
        req.handle_request()


    def handle_connections(self, db: Database):
        print("-----")
        conn, addr = self.server_socket.accept()
        print("[+] New connection established")

        while True:
            print("WAITING FOR CLIENT TO SEND SOMETHING")
            self.handle_client(conn, db) # TODO: threaded
