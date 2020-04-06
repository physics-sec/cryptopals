#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

fh = open('10.txt', 'r')
data = fh.read()
data = base64.b64decode(data)
fh.close()

key = b'YELLOW SUBMARINE'

iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

plaintext = decrypt_AES_CBC(data, key, iv)
plaintext = plaintext.decode('utf-8')
print(plaintext)
