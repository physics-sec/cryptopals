#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

# https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Signing

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
	dsa = DSA(p, q, evil_g)
	dsa.gen_keypair()

	z = random.randint(1, p - 1)
	r = pow(dsa.y, z, p) % q
	s =  r * dsa.invmod(z, q) % q

	r = int_to_bytes(r)
	s = int_to_bytes(s)

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
	dsa = DSA(p, q, evil_g)
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
