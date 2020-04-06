#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

key = rand_bytes(16)
iv  = key

print('key and iv:{}'.format(key.hex()))

def enc(user_input):
	return encrypt_AES_CBC(user_input, key, iv)

def dec(ct):
	pt = decrypt_AES_CBC(ct, key, iv)
	allowed = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
	for b in pt:
		if chr(b) not in allowed:
			return pt

def main():

	plaintext  = random_string(16*2 + 256).encode('utf-8')

	ciphertext = enc(plaintext)

	C1 = ciphertext[:16]
	badblock = rand_bytes(16)

	new_ciphertext = C1 + badblock + C1 + ciphertext[16*3:]

	pt = dec(new_ciphertext)

	P3 = pt[16*2:16*3]

	intermediate = xor(badblock, P3)

	key = xor(plaintext[:16], intermediate)

	print('found key :{}'.format(key.hex()))

if __name__ == '__main__':
	main()
