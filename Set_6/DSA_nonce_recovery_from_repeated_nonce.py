#!/usr/bin/python3
# -*- coding: utf-8 -*-

import re
import random
import hashlib

# https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Signing

class DSA():

	def __init__(self):
		self.p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
		self.q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
		self.g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
		self.prime_size = 512

	def gen_prime(self):
		process = subprocess.Popen(['openssl', 'prime', '-generate', '-bits', str(self.prime_size), '-hex'], stdout=subprocess.PIPE)
		prime = process.communicate()[0][:-1]
		prime = int(prime.decode('utf-8'), 16	)
		return prime

	def gen_keypair(self):
		self.x = random.randint(1, self.q - 1)
		self.y = pow(self.g, self.x, self.p)

	def egcd(self, a, b):
		if a == 0:
			return (b, 0, 1)
		else:
			g, y, x = self.egcd(b % a, a)
			return (g, x - (b // a) * y, y)

	def invmod(self, a, m):
		g, x, y = self.egcd(a, m)
		if g != 1:
			raise Exception('modular inverse does not exist')
		else:
			return x % m

	def int_to_bytes(self, integer):
		hex_string = "%x" % integer
		if len(hex_string) % 2 == 1:
			hex_string = '0' + hex_string
		return bytes.fromhex(hex_string)

	def bytes_to_int(self, byte_arr):
		return int.from_bytes(byte_arr, 'big')

	def sign(self, message, x=None, k=None):
		if x is None:
			x = self.x
		if k is None:
			k = random.randint(1, self.q - 1)

		r = pow(self.g, k, self.p) % self.q
		if r == 0:
			return self.sign(message, x, k)
		inv_k = self.invmod(k, self.q)
		sha1 = hashlib.sha1()
		sha1.update(message)
		dig = sha1.digest()
		h_m = self.bytes_to_int(dig)
		s = (inv_k * ( h_m + x * r )) % self.q
		if s == 0:
			return self.sign(message, x, k)
		return (self.int_to_bytes(r), self.int_to_bytes(s))

	def verify(self, r, s, message):
		r = self.bytes_to_int(r)
		s = self.bytes_to_int(s)
		assert r > 0 and r < self.q and s > 0 and s < self.q
		w = self.invmod(s, self.q)
		sha1 = hashlib.sha1()
		sha1.update(message)
		dig = sha1.digest()
		h_m = self.bytes_to_int(dig)
		u1  = h_m * w % self.q
		u2  = r * w % self.q
		v   = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
		return v == r

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
					digest = dsa.bytes_to_int(digest)
					x = recover_x(s1, k, digest, int(r1), q)
					print(f'private x: {x}\n')

	for key in keys:
		print(f'k:{key}')

if __name__ == '__main__':
	main()