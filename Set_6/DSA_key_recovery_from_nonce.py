#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

# https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Signing

def recover_x(s, k, H_m, r, q):
	dsa = DSA()
	inv_r = dsa.invmod(r, q)
	x = (((s * k) - H_m) * inv_r) % q
	return x

def main():
	dsa = DSA()
	msg = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

	y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

	r = 548099063082341131477253921760299949438196259240
	s = 857042759984254168557880549501802188789837994940

	inv_r = dsa.invmod(r, q)

	sha1 = hashlib.sha1()
	sha1.update(msg)
	digest = sha1.digest()
	digest = bytes_to_int(digest)

	for k in range(2**16):
		x = (((s * k) - digest) * inv_r) % q
		x = recover_x(s, k, digest, r, q)
		try:
			new_r, new_s = dsa.sign(msg, x, k)
			new_r = bytes_to_int(new_r)
			new_s = bytes_to_int(new_s)
		except Exception:
			continue
		if new_r == r and new_s == s:
			print(f'k:{k}')
			print(f'private key:{x}')
			return

def example():
	dsa = DSA()
	dsa.gen_keypair()
	msg = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
	r, s = dsa.sign(msg)

	valid = dsa.verify(r, s, msg)
	if valid:
		print('signature is valid')
	else:
		print('Fail!')

if __name__ == '__main__':
	main()
