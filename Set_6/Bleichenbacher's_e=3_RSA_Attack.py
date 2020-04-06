#!/usr/bin/python3
# -*- coding: utf-8 -*-

import gmpy2
import hashlib
import subprocess
import sys
sys.path.append("..")
from cryptolib import *

def main():
	rsa = RSA()
	rsa.gen_keypair(prime_size=1024)
	e, n = rsa.get_public_key()

	message = b'hi mom'
	real_signature = rsa.sign(message)
	print('real signature:{}\n'.format(real_signature.hex()))

	h = hashlib.sha256()
	h.update(message)
	digest = h.digest()

	ASNSHA256 = b"\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
	for null_pad in range(1000):
		block  = b'\x00\x01\xff\x00' + ASNSHA256 + digest

		block += b'\x00' * null_pad

		block_int = bytes_to_int(block)

		cube_root, rest = gmpy2.iroot_rem(block_int, 3)
		cube_root  = int(cube_root)
		cube_root += 1

		evil_signature = int_to_bytes(cube_root)

		valid = rsa.verify(evil_signature, message)

		if valid:
			print('spoofed signature:{}'.format(evil_signature.hex()))
			return
		else:
			pass

if __name__ == '__main__':
	main()
