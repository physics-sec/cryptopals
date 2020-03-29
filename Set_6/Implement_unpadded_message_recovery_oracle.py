#!/usr/bin/python3
# -*- coding: utf-8 -*-

import math
import string
import random
import subprocess

def randomString(stringLength):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

class RSA():

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

	def gen_prime(self):
		prime_size =  512
		process = subprocess.Popen(['openssl', 'prime', '-generate', '-bits', str(prime_size), '-hex'], stdout=subprocess.PIPE)
		prime = process.communicate()[0][:-1]
		prime = int(prime.decode('utf-8'), 16)
		return prime

	def gen_keypair(self):
		p = self.gen_prime()
		q = self.gen_prime()
		if p == q:
			return self.gen_keypair()
		self.n = p * q
		et = (p - 1) * (q - 1)
		self.e = 3
		self.d = self.invmod(self.e, et)

	def get_public_key(self):
		return (self.e, self.n)

	def get_private_key(self):
		return (self.d, self.n)

	def encrypt(self, plaintext, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		plaintext = bytes_to_int(plaintext)
		if plaintext > n:
			raise Exception('plaintext is longer than n')
		ciphertext = pow(plaintext, e, n)
		ciphertext = int_to_bytes(ciphertext)
		return ciphertext

	def decrypt(self, ciphertext):
		ciphertext = bytes_to_int(ciphertext)
		if ciphertext > self.n:
			raise Exception('ciphertext is longer than n')
		plaintext = pow(ciphertext, self.d, self.n)
		plaintext = int_to_bytes(plaintext)
		return plaintext

def int_to_bytes(integer):
	hex_string = "%x" % integer
	if len(hex_string) % 2 == 1:
		hex_string = '0' + hex_string
	return bytes.fromhex(hex_string)

def bytes_to_int(byte_arr):
	return int.from_bytes(byte_arr, 'big')

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def invmod(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m

"""
ct = pt ^ e mod n
pt = ct ^ d mod n

A = S ^ e mod n * pt ^ e mod n

-----------------------------------------
A ^ d mod n

((S ^ e mod n) * (pt ^ e mod n)) ^ d mod n

((S ^ e mod n) ^ d mod n) * ((pt ^ e mod n) ^ d mod n)

S * pt mod n
-----------------------------------------
"""

def main():
	rsa = RSA()
	rsa.gen_keypair()
	e, n = rsa.get_public_key()

	pt_original = randomString(20).encode('utf-8')
	print('secret plaintext:{}\n'.format(pt_original.decode('utf-8')))

	ct = rsa.encrypt(pt_original)
	ct_num = bytes_to_int(ct)

	S = random.randint(2, n - 1)
	S_enc_num = pow(S, e, n)
	new_ct_num = (S_enc_num * ct_num) % n

	new_ct = int_to_bytes(new_ct_num)

	pt_mod = rsa.decrypt(new_ct)
	pt_mod_num = bytes_to_int(pt_mod)

	pt_num = (pt_mod_num * invmod(S, n)) % n

	pt = int_to_bytes(pt_num)

	print('recovered:{}'.format(pt.decode('utf-8')))

if __name__ == '__main__':
	main()
