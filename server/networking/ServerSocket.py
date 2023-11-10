import socket
import selectors
from protocol import Request
from DatabaseUtils import Database
from protocol import Response

class ServerSocket:
    def __init__(self, port, host):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()


    def init_socket(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.server_socket.setblocking(False)
        self.sel.register(self.server_socket, selectors.EVENT_READ, self.accept)
        print(f"Server listening on port: {self.port}..")


    def handle_client(self, client_socket: socket.socket, db: Database):
        req = Request(client_socket, db)
        try:
            if not req.read_header():
                resp = Response(2107, 0, None).pack() # error response
                client_socket.sendall(resp)
                return
            req.handle_request()
        except:
            self.sel.unregister(client_socket)
            client_socket.close()
            print("[-] Lost connection")


    def handle_connections(self, db: Database):
        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, db)


    def accept(self, sock, mask):
        conn, addr = sock.accept()
        print("[+] New connection established")
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.handle_client)

