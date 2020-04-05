#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import random
import string
from Crypto.Cipher import AES

def randomString(stringLength):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

def rand_bytes(len):
	return os.urandom(len)

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

def encrypt_AES_ECB(plaintext, key):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def encrypt_AES_CBC(plaintext, key, iv):
	n = 16
	assert len(key) == n
	assert len(iv) == n
	plaintext = pad(plaintext)

	blocks = [plaintext[i:i+n] for i in range(0, len(plaintext), n)]
	ct = b''
	previus_block = iv

	for block in blocks:
		block_x = xor(block, previus_block)
		block_en = encrypt_AES_ECB(block_x, key)
		previus_block = block_en
		ct += block_en
	return ct

def CBC_MAC(msg, key, iv):
	return encrypt_AES_CBC(msg, key, iv)[-16:]

def verify_signature(key, msg, iv, mac):
	return mac == CBC_MAC(msg, key, iv)

# This just returns the second to last ciphertext block xored with the last plaintext block
def last_intermediate(plaintext, key, iv):
	n = 16
	assert len(key) == n
	assert len(iv) == n
	plaintext = pad(plaintext)

	blocks = [plaintext[i:i+n] for i in range(0, len(plaintext), n)]
	ct = b''
	previus_block = iv
	blocks_len = len(blocks)

	block_num = 0
	for block in blocks:
		block_num += 1
		block_x = xor(block, previus_block)
		if block_num == blocks_len:
			return block_x
		block_en = encrypt_AES_ECB(block_x, key)
		previus_block = block_en
		ct += block_en
	return ct

def get_evil_js(code, evil_code, key, iv,):

	normal_intermediate = last_intermediate(code, key, iv)

	evil_js  = evil_code
	evil_js += b'//'
	evil_js += b' ' * (16 - (len(evil_js) % 16))

	# get second to last block
	while True:
		second_to_last_pt_block  = randomString(16).encode('utf-8')
		intermediate = last_intermediate(evil_js + second_to_last_pt_block, key, iv)
		AES_padding = b'\x10' * 16
		second_to_last_ct = xor(intermediate, AES_padding)
		if second_to_last_ct[-1] ^ 1 == normal_intermediate[-1]:
			break

	evil_js += second_to_last_pt_block

	evil_js += xor(normal_intermediate[:-1], second_to_last_ct[:-1])

	return evil_js

def main():
	key = rand_bytes(16)
	iv  = rand_bytes(16)
	code = b"alert('MZA who was that?');\n"
	evil_js = b"alert('Ayo, the Wu is back!');"

	evil_js = get_evil_js(code, evil_js, key, iv)
	new_mac = CBC_MAC(evil_js, key, iv)
	mac = CBC_MAC(code, key, iv)

	assert new_mac == mac
	print('original mac:{}'.format(mac.hex()))
	print(evil_js)
	print('new mac     :{}'.format(new_mac.hex()))

if __name__ == '__main__':
	main()
