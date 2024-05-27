import json

def format_attack_data(type, id, data):

    json_data = json.loads('{"id":"10","attack":"ddos","arg1":"stealth,t5","arg2":"nono","arg3":"dd"}')

    json_data.update(data)

    print("json_data = " + str(json_data))

    return json_data