#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

def encryption_oracle(data):
	pre  = rand_bytes(random.randint(5, 10))
	post = rand_bytes(random.randint(5, 10))
	data = pre + data + post
	key  = rand_bytes(16)
	enc_type = random.randint(0,1)
	if enc_type == 0:
		# ECB
		return [encrypt_AES_ECB(pad(data), key), 'ECB']
	else:
		# CBC
		iv = rand_bytes(16)
		return [encrypt_AES_CBC(data, key, iv), 'CBC']

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
			data = 'A' * 60
			data = data.encode('utf-8')
			enc, enc_type  = encryption_oracle(data)
			enc_type_guess = guess(enc)
			if enc_type != enc_type_guess:
				print('FAIL after {:d} correct guesses'.format(i))
				exit()
			i += 1
			print('it was {}!'.format(enc_type_guess))
		except KeyboardInterrupt:
			break

if __name__ == '__main__':
	main()
