import mysql.connector
from env import *

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