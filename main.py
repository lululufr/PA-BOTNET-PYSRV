import socket
from env import *
import threading


def co():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("ecoute sur : " + str(HOST) + ":" + str(PORT))
        conn, addr = s.accept()
    return conn ,addr

def emission(conn, addr):
        while True:
            message = input("Message :")
            conn.sendall(message.encode())
            if message == 'quitter':
                break


def reception(conn,addr):
    print("Connection de :::: ", addr)
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f" Client: {data.decode()}")



def main():
    thread_emission = threading.Thread(target=emission, args=co())
    thread_reception = threading.Thread(target=reception, args=co())
    thread_emission.start()
    thread_reception.start()


if __name__ == "__main__":
    main()