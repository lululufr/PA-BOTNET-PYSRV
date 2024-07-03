import time
import socket
import threading
from queue import Queue
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

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



def emission(queue, conn, addr, sym_key, iv):
    # Gestion de l'envoi des messages
    running = True
    while running:
        data = queue.get()

        if data == b'stop-thread':
            running = False
            # print("stopping emission thread on ip " + str(addr))

        else:                
            # Chiffrer la donnée à envoyer
            cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
            enc_data = cipher.encrypt(pad(data, AES.block_size))

            # Récupération de la taille de la donnée à envoyer
            data_size = len(enc_data)
            # print("data size to send: " + str(data_size))

            # Chiffrer la taille de la donnée à envoyer
            cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
            enc_data_size = cipher.encrypt(pad(str(data_size).encode('utf-8'), AES.block_size))

            conn.sendall(enc_data_size)

            conn.sendall(enc_data)





def reception(queue, conn, addr, sym_key, iv, logger):
    running = True
    while running:
        try:
            # Reception de la taille de la donnée à recevoir (16 octets)
            enc_data_size = conn.recv(16)

            if not enc_data_size:
                print("Connection closed by client: " + str(addr))
                logger.info("Connection closed by client: " + str(addr))
                running = False
                queue.put(b'disconnected')  # Signaler la déconnexion au système

            else:
                # Déchiffrement de la taille de la donnée à recevoir
                cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
                data_size = int(unpad(cipher.decrypt(enc_data_size), AES.block_size).decode('utf-8'))

                # Reception de la donnée
                print("[+] data size to receive: " + str(data_size))
                logger.info("[+] data size to receive: " + str(data_size))

                received_data = 0
                enc_data = b''

                while received_data < data_size:
                    enc_data += conn.recv(data_size - received_data)
                    received_data = len(enc_data)
                    
                
                print("size data received : " + str(len(enc_data)))
                logger.info("size data received : " + str(len(enc_data)))


                # Déchiffrement de la donnée reçue
                cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
                data = unpad(cipher.decrypt(enc_data), AES.block_size)

                # Analyser le message reçu pour stopper le thread
                if data == 'stop-thread':
                    print("stopping reception thread on ip " + str(addr))
                    logger.info("stopping reception thread on ip " + str(addr))
                    running = False
                else:
                    queue.put(data)
                    print(str(len(data)) + " bytes received from " + str(addr))
                    logger.info(str(len(data)) + " bytes received from " + str(addr))

                    with open("received_data.txt", "wb") as f:
                        f.write(data)
                    # print("data received : " + str(data))

        except (ConnectionResetError, ConnectionAbortedError) as e:
            print("Connection error with " + str(addr) + ": " + str(e))
            logger.error("Connection error with " + str(addr) + ": " + str(e))
            running = False
            queue.put(b'disconnected')  # Signaler la déconnexion au système

        except Exception as e:
            print("Unexpected error: " + str(e))
            logger.error("Unexpected error: " + str(e))
            running = False
            queue.put(b'disconnected')  # Utiliser pour signaler une déconnexion inattendue


