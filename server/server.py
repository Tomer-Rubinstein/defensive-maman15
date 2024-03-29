from networking.ServerSocket import ServerSocket
from DatabaseUtils import Database
import os


def main():
    port = load_port("port.info")

    db = Database("defensive.db")
    db.init_tables()

    # all files created in this program will be put in ./uploaded_files
    os.makedirs(".\\uploaded_files\\", exist_ok=True)
    os.chdir(".\\uploaded_files")

    server_socket = ServerSocket(port, "127.0.0.1")
    server_socket.init_socket()
    server_socket.handle_connections(db)


def load_port(filename: str) -> int:
    """
    loads port from filename (param), returns the file's content converted to integer.
    if failed, returns default port and outputs a warning message.

    :param filename: path to file
    :return: port
    """
    port = 1357 # default port value
    try:
        with open(filename, "r") as file:
            port = int(file.read())
    except:
        print("[WARNING] port.info file couldn't be read, using default port:", port)
    return port


if __name__ == "__main__":
    main()
