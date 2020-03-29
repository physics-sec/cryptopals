#!/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess

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

def gen_prime():
	prime_size =  512
	process = subprocess.Popen(['openssl', 'prime', '-generate', '-bits', str(prime_size), '-hex'], stdout=subprocess.PIPE)
	prime = process.communicate()[0][:-1]
	prime = int(prime.decode('utf-8'), 16	)
	return prime

class RSA():

	def gen_keypair(self):
		p = gen_prime()
		q = gen_prime()
		if p == q:
			return self.gen_keypair()
		self.n = p * q
		et = (p - 1) * (q - 1)
		self.e = 3
		self.d = invmod(self.e, et)

	def get_public_key(self):
		return [self.e, self.n]

	def get_public_key(self):
		return [self.d, self.n]

	def encrypt(self, plaintext, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		plaintext  = plaintext.hex()
		plaintext  = int(plaintext, 16)
		if plaintext > self.n:
			raise Exception('plaintext is longer than n')
		ciphertext = pow(plaintext, e, n)
		ciphertext = "%x" % ciphertext
		ciphertext = bytes.fromhex(ciphertext)
		return ciphertext

	def decrypt(self, ciphertext):
		ciphertext = ciphertext.hex()
		ciphertext = int(ciphertext, 16)
		if ciphertext > self.n:
			raise Exception('ciphertext is longer than n')
		plaintext  = pow(ciphertext, self.d, self.n)
		plaintext = "%x" % plaintext
		plaintext = bytes.fromhex(plaintext)
		return plaintext

def main():
	rsa = RSA()
	rsa.gen_keypair()
	ct = rsa.encrypt(b'test string')
	pt = rsa.decrypt(ct).decode('utf-8')
	print(pt)

if __name__ == '__main__':
	main()

