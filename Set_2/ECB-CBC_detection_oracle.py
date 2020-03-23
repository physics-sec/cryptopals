#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import random
from Crypto.Cipher import AES

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

def encrypt_AES_ECB(plaintext, key, do_pad=True):
	assert len(key) == 128/8
	if do_pad:
		plaintext = pad(plaintext)
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
		block_en = encrypt_AES_ECB(block_x, key, False)
		previus_block = block_en
		ct += block_en
	return ct

def rand_bytes(len):
	return os.urandom(len)

def encryption_oracle(data):
	pre  = rand_bytes(random.randint(5, 10))
	post = rand_bytes(random.randint(5, 10))
	data = pre + data + post
	key  = rand_bytes(16)
	enc_type = random.randint(0,1)
	if enc_type == 0:
		# ECB
		return [encrypt_AES_ECB(data, key), 'ECB']
	else:
		# CBC
		iv = rand_bytes(16)
		return [encrypt_AES_CBC(data, key, iv), 'CBC']

def index_of_coincidence(data):
	data_len = len(data)
	d = data_len * (data_len - 1)
	frec = {}
	for b in data:
		if b not in frec:
			frec[b]  = 1
		else:
			frec[b] += 1
	ic = 0
	for b in frec:
		ic += (frec[b] * (frec[b] - 1)) / d
	return ic

def guess(ciphertext):
	ic = index_of_coincidence(ciphertext)
	if ic < 0.009:
		return 'CBC'
	else:
		return 'ECB'

def main():
	i = 0
	while  True:
		try:
			#data = input('enter data:')
			data = 'A' * 60
			data = data.encode('utf-8')
			enc, enc_type  = encryption_oracle(data)
			enc_type_guess = guess(enc)
			if enc_type != enc_type_guess:
				print('FAIL after {:d} correct guesses'.format(i))
				exit()
			i += 1
			print('it was {}!'.format(enc_type_guess))
			#input('[enter]')
		except KeyboardInterrupt:
			break

if __name__ == '__main__':
	main()
