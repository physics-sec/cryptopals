#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

key = rand_bytes(16)
secret = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
secret = base64.b64decode(secret)
pre = rand_bytes( random.randint(0,50) )

def encrypt_AES_ECB_wrap(plaintext):
	plaintext = plaintext + secret
	plaintext = pad(plaintext)
	return encrypt_AES_ECB(plaintext, key)

def get_challenge_info():
	n = 16
	iguales_prev = 0
	for i in range(0, 16 + 1):
		test1 = b'_' * i + b'A'
		test2 = b'_' * i + b'B'
		result1 = encrypt_AES_ECB_wrap( test1 )
		result1 = [result1[i:i+n] for i in range(0, len(result1), n)]
		result2 = encrypt_AES_ECB_wrap( test2 )
		result2 = [result2[i:i+n] for i in range(0, len(result2), n)]
		iguales = 0
		for j in range(1, len(result1)):
			if result1[-j] == result2[-j]:
				iguales += 1
			else:
				break
		if iguales < iguales_prev:
			num_secret_blocks = iguales + 1
			padding = b'_' * i
			break
		else:
			iguales_prev = iguales

	ct_padding = encrypt_AES_ECB_wrap(padding)
	len_padding = len(ct_padding)
	i = 0
	len_new = 0
	while len_new <= len_padding:
		i += 1
		ct_new = encrypt_AES_ECB_wrap( padding + b'A' * i )
		len_new = len(ct_new)

	bs = len_new - len_padding

	num_blocks = int( len(ct_padding) / bs )
	offset_blocks = num_blocks - num_secret_blocks

	key_size  = bs * num_secret_blocks - i

	return [padding, bs, key_size, offset_blocks]

def recover_secret():
	padding, bs, secret_len, offset_blocks = get_challenge_info()
	print('padding size:{:d}'.format(len(padding)))
	print('block size:{:d}'.format(bs))
	print('secret size:{:d}'.format(secret_len))
	print('offset blocks:{:d}'.format(offset_blocks))

	recovered = b''
	while len(recovered) < secret_len:
		base  = padding
		base += b'A' * ( bs - (len(recovered) % bs) - 1 )

		blocks_recovered = int( len(recovered) / bs )
		looking_for = encrypt_AES_ECB_wrap(base)
		looking_for = looking_for[bs * (blocks_recovered + offset_blocks):bs*(blocks_recovered+offset_blocks+1)]

		for b in range(0xff + 1):
			guess = bytes([b])

			ct = encrypt_AES_ECB_wrap(base + recovered + guess)
			ct = ct[bs * (blocks_recovered + offset_blocks):bs*(blocks_recovered+offset_blocks+1)]

			if ct == looking_for:
				recovered += guess
				break

	print('\nsecret:\n{}'.format(recovered.decode('utf-8')))

if __name__ == '__main__':
	recover_secret()
