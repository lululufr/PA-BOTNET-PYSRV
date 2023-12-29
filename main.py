import socket
from env import *
import threading


def connection(port,host):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        print("ecoute sur : "+ str(host) +":"+ str(port))

        conn, addr = s.accept()
        with conn:
            print("Connection de :::: ", addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"Received from Rust: {data.decode()}")

                message = input("Message :")
                conn.sendall(message.encode())

                if message == 'quitter':
                    break


def main():

    co = threading.Thread(target=connection, args=(PORT,HOST))
    co.start()

if __name__ == "__main__":
    main()