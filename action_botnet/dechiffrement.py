# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# import base64


import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

data = b"secret"
key = b'1234567890123456'
iv = b'1234567890123456'

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))
iv = (cipher.iv).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'iv':iv, 'ciphertext':ct})
print(result)


# data = b'hello world'

# key = get_random_bytes(16)

# cipher = AES.new(key, AES.MODE_CBC)
# ciphertext, tag = cipher.encrypt_and_digest(data)
# nonce = cipher.nonce

# print("data:", data.decode('utf-8'))
# print(ciphertext)
# print("base64:", base64.b64encode(ciphertext).decode('utf-8'))

