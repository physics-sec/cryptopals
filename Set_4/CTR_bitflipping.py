#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import struct
import random
from Crypto.Cipher import AES

def rand_bytes(len):
	return os.urandom(len)

key = rand_bytes(16)
nonce  = rand_bytes(8)

def xor(x1, x2):
    assert len(x1) == len(x2)
    b_list = list(map(lambda x,y: x^y, x1, x2))
    return bytes( b_list )

def encrypt_AES_ECB(key, plaintext):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def CTR(key, nonce, msg):
	msg_len = len(msg)
	assert len(nonce) == 8
	n = 16
	count = -1
	ciphertext = b''
	for count in range( msg_len//n ):
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(key, plaintext)
		ciphertext += xor(ct, msg[n*count:n*(count+1)])

	if msg_len % n != 0:
		count += 1
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(key, plaintext)
		ciphertext += xor(ct[:msg_len % n], msg[n*count:])
	return ciphertext

def enc(user_input):
	data  = b"comment1=cooking%20MCs;userdata="
	data += user_input.replace(b',', b'').replace(b'=', b'')
	data += b";comment2=%20like%20a%20pound%20of%20bacon"
	ct = CTR(key, nonce, data)
	return ct

def dec(ct):
	pt = CTR(key, nonce, ct)
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
