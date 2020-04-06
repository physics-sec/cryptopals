#!/usr/bin/python3
# -*- coding: utf-8 -*-

import re
import sys
sys.path.append("..")
from cryptolib import *

# https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Signing

"""
m = message

k = random

r = g ^ k mod p

s = k⁻¹(H(m) + x * r) mod q

if k is equal in two signatures...

r is the same

s1 = k⁻¹(H(m1) + x * r) mod q
s2 = k⁻¹(H(m2) + x * r) mod q


s1 - s2 mod q = k⁻¹(H(m1) + x * r) - k⁻¹(H(m2) + x * r) mod q

k = (H(m1) + x * r) - (H(m2) + x * r) mod q
     --------------------------------
     			s1 - s2

k = H(m1) + x * r - H(m2) - x * r     mod q
     --------------------------------
     			s1 - s2

k = H(m1) - H(m2)   mod q
    --------------
       s1 - s2

"""

def recover_x(s, k, H_m, r, q):
	dsa = DSA()
	inv_r = dsa.invmod(r, q)
	x = (((s * k) - H_m) * inv_r) % q
	return x

def main():
	dsa = DSA()
	msg = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

	fh = open('44.txt', 'r')
	data = fh.read()
	fh.close()

	matches = re.findall(r'msg: (.*?)\ns: (.*?)\nr: (.*?)\nm: (.*)\n?', data)
	
	keys = []

	for msg1, s1, r1, m1 in matches:
		for msg2, s2, r2, m2 in matches:
			if msg1 != msg2 and r1 == r2:

				m1 = int(m1, 16)
				m2 = int(m2, 16)

				s1 = int(s1)
				s2 = int(s2)

				k = ((m1 - m2) % q) * dsa.invmod((s1 - s2) % q, q) % q
				if k not in keys:
					keys.append(k)
				if len(keys) == 1:
					sha1 = hashlib.sha1()
					sha1.update(msg1.encode('utf-8'))
					digest = sha1.digest()
					digest = bytes_to_int(digest)
					x = recover_x(s1, k, digest, int(r1), q)
					print(f'private x: {x}\n')

	for key in keys:
		print(f'k:{key}')

if __name__ == '__main__':
	main()
