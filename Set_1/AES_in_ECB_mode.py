#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import sys
sys.path.append("..")
from cryptolib import *

fh = open('7.txt', 'r')
data = fh.read()
data = base64.b64decode(data)
fh.close()

key = b'YELLOW SUBMARINE'

pt = decrypt_AES_ECB(data, key)
pt = pt.decode('utf-8')
print(pt)
