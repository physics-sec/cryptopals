#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

key = rand_bytes(16)
nonce  = rand_bytes(8)

def enc(user_input):
	data  = b"comment1=cooking%20MCs;userdata="
	data += user_input.replace(b',', b'').replace(b'=', b'')
	data += b";comment2=%20like%20a%20pound%20of%20bacon"
	ct = CTR(data, key, nonce)
	return ct

def dec(ct):
	pt = CTR(ct, key, nonce)
	#if pt != b'':
	#	print(pt)
	return pt

def bit_flip():
	# comment1=cooking %20MCs;userdata= ?admin?true;comm ent2=%20like%20a %20pound%20of%20 bacon

	payload  = bytes( [ ord(';') ^ (1 << random.randint(0, 7))] )
	payload += b'admin'
	payload += bytes( [ ord('=') ^ (1 << random.randint(0, 7))] )
	payload += b'true'

	pos_1 = 6 + 16 * 2
	pos_2 = 0 + 16 * 2

	ct_original = enc(payload)
	for i in range(8):
		ct  = ct_original[:pos_1]
		ct += bytes( [ct_original[pos_1] ^ (1 << i)] )
		ct += ct_original[pos_1+1:]
		pt = dec(ct)
		if b"admin=true" in pt:
			ct_original = ct
			for i in range(8):
				ct  = ct_original[:pos_2]
				ct += bytes( [ct_original[pos_2] ^ (1 << i)] )
				ct += ct_original[pos_2+1:]
				pt = dec(ct)
				if b";admin=true;" in pt:
					print('exito!')
					print('ct:')
					print(ct)
					print('pt')
					print(pt)
					return

if __name__ == '__main__':
	bit_flip()
