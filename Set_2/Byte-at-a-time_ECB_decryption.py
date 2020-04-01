#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import base64
from Crypto.Cipher import AES

def rand_bytes(len):
	return os.urandom(len)

key = rand_bytes(16)
secret = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
secret = base64.b64decode(secret)

def pad(s, pad_len=16):
	s_len = len(s)
	resto = s_len % pad_len
	b_len = pad_len - resto
	pad = bytes([ b_len ]) * b_len
	return s + pad

def encrypt_AES_ECB(plaintext):
	plaintext = plaintext + secret
	plaintext = pad(plaintext)
	cipher = AES.new(key, AES.MODE_ECB)
	ct = cipher.encrypt(plaintext)
	return ct

def get_block_size_and_secret_len():
	ct_normal = encrypt_AES_ECB(b'')
	len_normal = len(ct_normal)

	i = 0
	len_new = 0
	while len_new <= len_normal:
		i += 1
		ct_new = encrypt_AES_ECB( b'A' * i )
		len_new = len(ct_new)
	bs = len_new - len_normal

	blocks_len = len(ct_normal) // bs 
	key_size  = bs * (blocks_len - 1)
	key_size += bs - i
	return [bs, key_size]

def recover_secret():
	bs, secret_len = get_block_size_and_secret_len()
	print('block size:{:d}'.format(bs))
	print('secret size:{:d}'.format(secret_len))

	recovered = b''
	while len(recovered) < secret_len:
		base = b'A' * ( bs - (len(recovered) % bs) - 1 )

		blocks_recovered = int( len(recovered) / bs )
		looking_for = encrypt_AES_ECB(base)
		looking_for = looking_for[bs * blocks_recovered:bs*(blocks_recovered+1)]

		for b in range(0xff + 1):
			guess = bytes([b])

			ct = encrypt_AES_ECB(base + recovered + guess)
			ct = ct[bs * blocks_recovered:bs*(blocks_recovered+1)]

			if ct == looking_for:
				recovered += guess
				break

	print('\nsecret:\n{}'.format(recovered.decode('utf-8')))

if __name__ == '__main__':
	recover_secret()
