import socket
import threading
from queue import Queue

def handle_client(host, port, queue):
    # Création du socket et écoute sur le port spécifié
    running = True
    while running:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setblocking(1)
            s.bind((host, port))
            s.listen()
            print("ecoute sur : " + str(host) + ":" + str(port))
            conn, addr = s.accept()
        return conn, addr

def emission(queue, conn, addr):
    # Gestion de l'envoi des messages
    running = True
    while running:
        message = queue.get()
        if message == 'stop-thread':
            running = False
            print("stopping emission thread on ip " + str(addr))
        else:                
            conn.sendall(message)
            # print("data sent to " + str(addr))

# def reception(queue, conn, addr):
#     # Gestion de la réception des messages
#     running = True
#     while running:
#         data = conn.recv(1024)
#         if not data:
#             running = False
#             print("stopping reception thread on ip " + str(addr))
#         else:
#             queue.put(data)
#             print("data received from " + str(addr))

def reception(queue, conn, addr):
    running = True
    while running:
        try:
            data = conn.recv(1024)
            if not data:
                running = False
                print("stopping reception thread on ip " + str(addr))
            else:
                queue.put(data)
                # print("data received from " + str(addr))
        except BlockingIOError:
            continue  # Continue l'écoute si aucune donnée n'est disponible