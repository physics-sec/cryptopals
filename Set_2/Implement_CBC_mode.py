#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import codecs
from Crypto.Cipher import AES

def xor(x1, x2): 
    assert len(x1) == len(x2) 
    b_list = list(map(lambda x,y: x^y, x1, x2)) 
    return bytes( b_list ) 

def decrypt_AES_ECB(data, key):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	pt = cipher.decrypt(data)
	return pt

def decrypt_AES_CBC(ciphertext, key, iv):
	n = 16
	assert len(key) == n
	assert len(iv) == n
	ciphertext_len = len(ciphertext)
	assert ciphertext_len % n == 0

	blocks = [ciphertext[i:i+n] for i in range(0, ciphertext_len, n)]
	pt = []
	previus_block = iv

	for block in blocks:
		d_block = decrypt_AES_ECB(block, key)
		pt_block = xor(d_block, previus_block)
		pt.append(pt_block)
		previus_block = block
	return b''.join(pt)


fh = open('10.txt', 'r')
data = fh.read()
data = base64.b64decode(data)
fh.close()

key = b'YELLOW SUBMARINE'

iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

plaintext = decrypt_AES_CBC(data, key, iv)
plaintext = plaintext.decode('utf-8')
print(plaintext)
