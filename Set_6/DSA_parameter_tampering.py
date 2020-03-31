#!/usr/bin/python3
# -*- coding: utf-8 -*-

import random
import hashlib

# https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Signing

class DSA():

	def __init__(self, p, q, g):
		self.p = p
		self.q = q
		self.g = g
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
		#if r == 0:
		#	return self.sign(message, x, k)
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
		#assert r > 0 and r < self.q and s > 0 and s < self.q
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
z = random mod q

g = q - 1

r = ((y^z) % p) % q

s = r * z⁻¹ mod q
1 = s⁻¹ * (r * z⁻¹) mod q
(r * z⁻¹)⁻¹ = s⁻¹ mod q
s⁻¹ mod q = (r * z⁻¹)⁻¹ = r⁻¹ * z ???????????????????

	verification:

w = s⁻¹ mod q = r⁻¹ * z

u1 = H(m) * w mod q = H(m) * r⁻¹ * z mod q

u2 = r * w mod q = r * r⁻¹ * z = z

v = ((g^u1) * (y^u2) mod p) mod q = ((q-1)^((H(m) * r⁻¹ * z) mod q) * (y^u2) mod p) mod q
v = ((q-1)^((H(m) * r⁻¹ * z) mod q) * (y^z) mod p) mod q
v = (  1 * (y^z) mod p) mod q = r
v = (q-1 * (y^z) mod p) mod q = ?????

"""

def attack2():
	p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
	g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

	evil_g = p + 1
	dsa = DSA(p,q, evil_g)
	dsa.gen_keypair()

	z = random.randint(1, p - 1)
	r = pow(dsa.y, z, p) % q
	s =  r * dsa.invmod(z, q) % q

	r = dsa.int_to_bytes(r)
	s = dsa.int_to_bytes(s)

	valid = dsa.verify(r, s, b'any message')
	if valid:
		print('is valid')
	else:
		print('is invalid')

"""
m = message

k = random

	signature:

r = g ^ k mod p

s = k⁻¹(H(m) + x * r) mod q

if g == 0 then r = 0
if g == kp then r = 0

if r == 0

s = (k⁻¹ * H(m)) mod q

	verification:

w = s⁻¹ mod q

u1 = H(m) * w mod q

u2 = r * w moq = 0

v = (g^u1*y*u2 mod p) mod q == g^u1 mod p mod q == kp^u1 mod p mod q == 0

v = r = 0

"""

def attack1():
	p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
	g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

	evil_g = p * random.randint(0, 3)
	dsa = DSA(p,q, evil_g)
	dsa.gen_keypair()

	r, s = dsa.sign(b'some message')

	valid = dsa.verify(r, s, b'another message')
	if valid:
		print('is valid')
	else:
		print('is invalid')

if __name__ == '__main__':
	attack1()
	attack2()
