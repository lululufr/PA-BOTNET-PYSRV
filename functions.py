import json

def format_attack_data(type, id, data):

    json_data = json.loads('{"action":"' + type + '", "id":"' + str(id) + '"}')

    json_data.update(data)

    print("json_data = " + str(json_data))

    return json_data