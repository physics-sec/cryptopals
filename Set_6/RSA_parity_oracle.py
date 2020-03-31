#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import subprocess

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
		prime_size =  1024
		process = subprocess.Popen(['openssl', 'prime', '-generate', '-bits', str(prime_size), '-hex'], stdout=subprocess.PIPE)
		prime = process.communicate()[0][:-1]
		prime = int(prime.decode('utf-8'), 16	)
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
		return [self.e, self.n]

	def get_private_key(self):
		return [self.d, self.n]

	def int_to_bytes(self, integer):
		hex_string = "%x" % integer
		if len(hex_string) % 2 == 1:
			hex_string = '0' + hex_string
		return bytes.fromhex(hex_string)

	def bytes_to_int(self, byte_arr):
		return int.from_bytes(byte_arr, 'big')

	def encrypt(self, plaintext, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		plaintext = self.bytes_to_int(plaintext)
		if plaintext > n:
			raise Exception('plaintext is longer than n')
		ciphertext = pow(plaintext, e, n)
		ciphertext = self.int_to_bytes(ciphertext)
		return ciphertext

	def decrypt(self, ciphertext):
		ciphertext = self.bytes_to_int(ciphertext)
		#if ciphertext > self.n:
		#	raise Exception('ciphertext is longer than n')
		plaintext = pow(ciphertext, self.d, self.n)
		return plaintext & 1

"""
c = m ^ e mod p

k = r ^ e mod p

(c*k) ^ d mod p
(c^ d mod p)*(k^ d mod p)
m * r
"""

def main():
	rsa = RSA()
	rsa.gen_keypair()
	e, n = rsa.get_public_key()
	data = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
	ct = rsa.encrypt(data)
	ct = rsa.bytes_to_int(ct)

	bound_min = 1
	bound_max = None
	while True:

		if bound_max is None:
			mult = bound_min * 2
		else:
			mult = (bound_min + bound_max) // 2

		test_ct = ct * pow(mult, e, n)
		test_ct = rsa.int_to_bytes(test_ct)
		parity = rsa.decrypt(test_ct)

		if parity == 1:
			bound_max = mult
		else:
			bound_min = mult

		print('\nmin')
		print(bound_min)

		print('\nmax')
		print(bound_max)

		if bound_max is not None and bound_min == bound_max - 1:
			print(rsa.int_to_bytes(n//bound_min))
			print('')
			return

if __name__ == '__main__':
	main()
