from networking.ServerSocket import ServerSocket
from DatabaseUtils import Database
import os

def main():
    port = load_port("port.info")
    
    # bla
    os.makedirs(".\\uploaded_files\\", exist_ok=True)
    os.chdir(".\\uploaded_files")

    db = Database("defensive.db")
    db.init_tables()

    server_socket = ServerSocket(port, "127.0.0.1")
    server_socket.init_socket()
    server_socket.handle_connections(db)


"""
loads port from filename (param), returns the file's content converted to integer.
if failed, returns default port and outputs a warning message.

@param filename (str)
@return port (int)
"""
def load_port(filename: str) -> int:
    port = 1357 # default port value
    try:
        with open(filename, "r") as file:
            port = int(file.read())
    except:
        print("[WARNING] port.info file couldn't be read, using default port:", port)
    return port


if __name__ == "__main__":
    main()
