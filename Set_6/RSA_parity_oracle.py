#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

"""
c = m ^ e mod p

k = r ^ e mod p

(c*k) ^ d mod p
(c^ d mod p)*(k^ d mod p)
m * r
"""

def get_parity(rsa, test_ct):
	pt = rsa.decrypt(test_ct)
	last_byte = pt[-1]
	last_bit =  last_byte & 1
	return last_bit

def main():
	rsa = RSA()
	rsa.gen_keypair(prime_size=1024)
	e, n = rsa.get_public_key()
	data = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
	ct = rsa.encrypt(data)
	ct = bytes_to_int(ct)

	bound_min = 1
	bound_max = None
	while True:

		if bound_max is None:
			mult = bound_min * 2
		else:
			mult = (bound_min + bound_max) // 2

		test_ct = ct * pow(mult, e, n)
		test_ct = int_to_bytes(test_ct)
		parity = get_parity(rsa, test_ct)

		if parity == 1:
			bound_max = mult
		else:
			bound_min = mult

		print('\nmin')
		print(bound_min)

		print('\nmax')
		print(bound_max)

		if bound_max is not None and bound_min == bound_max - 1:
			print(int_to_bytes(n//bound_min))
			print('')
			return

if __name__ == '__main__':
	main()
