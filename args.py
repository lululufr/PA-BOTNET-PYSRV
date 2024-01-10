import sys


attacks = [
    {
        "name": "ddos",
        "args": [
            {
                "name": "--address",
                "type": "str",
                "help": "Adresse de la cible"
            },
            {
                "name": "--time",
                "type": "int",
                "help": "Temps de l'attaque"
            }
        ]
    },
    {
        "name": "crack",
        "args": [
            {
                "name": "--hash",
                "type": "str",
                "help": "Hash à cracker"
            },
            {
                "name": "--wordlist",
                "type": "str",
                "help": "Wordlist à utiliser"
            }
        ]
    }
]

if sys.argv[1] == "-h" or sys.argv[1] == "--help":
    print("Usage: python3 main.py [OPTION]... [ARG]... [HOST | GROUP]\n")

    print("Attacks :")
    for attack in attacks:
        print(" [+] " + attack["name"] + " :")
        for arg in attack["args"]:
            print("\t" + arg["name"] + " (" + arg["type"] + ") : " + arg["help"])
    
    print("\nHost or Group:")
    print("  -H, --host HOST : permet de sélectionner un ordinateur. Pour sélectionner plusieurs hosts, il faut les séparer par des virgules")
    print("  -G, --group GROUP : permet de sélectionner un groupe d'ordinateur. Pour sélectionner plusieurs groupes, il faut les séparer par des virgules (ex: 'ESGI,PARIS')")
    # print("Options:")
    # print("  --ddos --address --time")
    # print("  --crack --hash --wordlist")
    exit(0)

