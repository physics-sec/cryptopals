#!/usr/bin/python3
# -*- coding: utf-8 -*-

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
			return self.sign(messag, x, k)
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
	digest = dsa.bytes_to_int(digest)

	for k in range(2**16):
		x = (((s * k) - digest) * inv_r) % q
		try:
			new_r, new_s = dsa.sign(msg, x, k)
			new_r = dsa.bytes_to_int(new_r)
			new_s = dsa.bytes_to_int(new_s)
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
