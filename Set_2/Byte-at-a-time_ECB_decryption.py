#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

key = rand_bytes(16)
secret = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
secret = base64.b64decode(secret)

def encrypt_AES_ECB_wrap(plaintext):
	plaintext = plaintext + secret
	plaintext = pad(plaintext)
	return encrypt_AES_ECB(plaintext, key)

def get_block_size_and_secret_len():
	ct_normal = encrypt_AES_ECB_wrap(b'')
	len_normal = len(ct_normal)

	i = 0
	len_new = 0
	while len_new <= len_normal:
		i += 1
		ct_new = encrypt_AES_ECB_wrap( b'A' * i )
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
		looking_for = encrypt_AES_ECB_wrap(base)
		looking_for = looking_for[bs * blocks_recovered:bs*(blocks_recovered+1)]

		for b in range(0xff + 1):
			guess = bytes([b])

			ct = encrypt_AES_ECB_wrap(base + recovered + guess)
			ct = ct[bs * blocks_recovered:bs*(blocks_recovered+1)]

			if ct == looking_for:
				recovered += guess
				break

	print('\nsecret:\n{}'.format(recovered.decode('utf-8')))

if __name__ == '__main__':
	recover_secret()
