import json

def format_attack_data(type, id, data):

    json_data = json.loads('{"id":"'+str(id)+'","attack":"'+type+'","arg1":"stealth,t5","arg2":"nono","arg3":""}')

    json_data.update(data)

    print("json_data = " + str(json_data))

    return json_data