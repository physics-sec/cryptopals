#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import random
import string
from Crypto.Cipher import AES

def rand_bytes(len):
	return os.urandom(len)

key = rand_bytes(16)
iv  = rand_bytes(16)

def unpad(s):
	return s[:-s[-1]]

def pad(s, pad_len=16):
	s_len = len(s)
	resto = s_len % pad_len
	b_len = pad_len - resto
	pad = bytes([ b_len ]) * b_len
	return s + pad

def xor(x1, x2):
	assert len(x1) == len(x2)
	r = b''
	for i in range(len(x1)):
		r += bytes([ x1[i] ^ x2[i] ])
	return r

def encrypt_AES_ECB(plaintext):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def encrypt_AES_CBC(plaintext):
	n = 16
	assert len(key) == n
	assert len(iv) == n
	plaintext = pad(plaintext)

	blocks = [plaintext[i:i+n] for i in range(0, len(plaintext), n)]
	ct = b''
	previus_block = iv

	for block in blocks:
		block_x = xor(block, previus_block)
		block_en = encrypt_AES_ECB(block_x)
		previus_block = block_en
		ct += block_en
	return ct

def decrypt_AES_ECB(data):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	pt = cipher.decrypt(data)
	return pt

def decrypt_AES_CBC(ciphertext):
	n = 16
	assert len(key) == n
	assert len(iv) == n
	ciphertext_len = len(ciphertext)
	assert ciphertext_len % n == 0

	blocks = [ciphertext[i:i+n] for i in range(0, ciphertext_len, n)]
	pt = b''
	previus_block = iv

	for block in blocks:
		d_block = decrypt_AES_ECB(block)
		pt_block = xor(d_block, previus_block)
		pt += pt_block
		previus_block = block
	pt = unpad(pt)
	return pt

def enc(user_input):
	data  = b"comment1=cooking%20MCs;userdata="
	data += user_input.replace(b',', b'').replace(b'=', b'')
	data += b";comment2=%20like%20a%20pound%20of%20bacon"
	ct = encrypt_AES_CBC(data)
	return ct

def dec(ct):
	pt = decrypt_AES_CBC(ct)
	if pt != b'':
		pass#print(pt)
	return b";admin=true;" in pt

def randomString(stringLength):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

def bit_flip():
	while True:
		rs = randomString(40).encode('utf-8')
		ct_original = enc(rs)
		for i in range(len(ct_original)):
			for j in range(8):
				ct  = ct_original[:i]
				ct += bytes( [ct_original[i] ^ (1 << j)] )
				ct += ct_original[i+1:]
				if dec(ct):
					print('exito!')
					print('i:{:d}'.format(i))
					print('j:{:d}'.format(j))
					print('ct:')
					print(ct)
					print('ct_original:')
					print(ct_original)
					print('pt:')
					print(decrypt_AES_CBC(ct))
					return

if __name__ == '__main__':
	bit_flip()
