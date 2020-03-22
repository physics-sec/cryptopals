#!/usr/bin/python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
import base64

#$ openssl enc -aes-128-ecb -d -a -in 7.txt -K $(echo "YELLOW SUBMARINE" | xxd -p) -iv 1

def decrypt_AES_ECB(data, key):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	pt = cipher.decrypt(data)
	return pt

fh = open('7.txt', 'r')
data = fh.read()
data = base64.b64decode(data)
fh.close()

key = b'YELLOW SUBMARINE'

pt = decrypt_AES_ECB(data, key)
pt = pt.decode('utf-8')
print(pt)
