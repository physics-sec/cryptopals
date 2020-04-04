#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import random
import string
from Crypto.Cipher import AES

def rand_bytes(len):
	return os.urandom(len)

key = rand_bytes(16)
iv  = key

print('key and iv:{}'.format(key.hex()))

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
	return encrypt_AES_CBC(user_input)

def dec(ct):
	pt = decrypt_AES_CBC(ct)
	allowed = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
	for b in pt:
		if chr(b) not in allowed:
			return pt

def randomString(stringLength):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def main():

	plaintext  = randomString(16*2 + 256).encode('utf-8')

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
