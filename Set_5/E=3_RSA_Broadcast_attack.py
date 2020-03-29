#!/usr/bin/python3
# -*- coding: utf-8 -*-

import gmpy2
import random
import string
import subprocess
from functools import reduce

def randomString(stringLength):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

def chinese_remainder(n, a):
	sum = 0
	prod = reduce(lambda a, b: a*b, n)
	for n_i, a_i in zip(n, a):
		p = prod // n_i
		sum += a_i * mul_inv(p, n_i) * p
	return sum % prod

def mul_inv(a, b):
	b0 = b
	x0, x1 = 0, 1
	if b == 1: return 1
	while a > 1:
		q = a // b
		a, b = b, a%b
		x0, x1 = x1 - q * x0, x0
	if x1 < 0: x1 += b0
	return x1

class RSA():

	def __init__(self):
		self.plaintext = randomString(100).encode('utf-8')
		print('plaintext is:{}'.format(self.plaintext.decode('utf-8')))

	def egcd(self,a, b):
		if a == 0:
			return (b, 0, 1)
		else:
			g, y, x = self.egcd(b % a, a)
			return (g, x - (b // a) * y, y)

	def invmod(self,a, m):
		g, x, y = self.egcd(a, m)
		if g != 1:
			raise Exception('modular inverse does not exist')
		else:
			return x % m

	def gen_prime(self):
		prime_size = 512
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

	def get_public_key(self):
		return [self.d, self.n]

	def int_to_bytes(self, integer):
		hex_string = "%x" % integer
		if len(hex_string) % 2 == 1:
			hex_string = '0' + hex_string
		return bytes.fromhex(hex_string)

	def bytes_to_int(self, byte_arr):
		return int.from_bytes(byte_arr, 'big')

	def encrypt(self, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		plaintext = self.bytes_to_int(self.plaintext)
		if plaintext > n:
			raise Exception('plaintext is longer than n')
		ciphertext = pow(plaintext, e, n)
		ciphertext = self.int_to_bytes(ciphertext)
		return ciphertext

	def decrypt(self, ciphertext):
		ciphertext = self.bytes_to_int(ciphertext)
		if ciphertext > self.n:
			raise Exception('ciphertext is longer than n')
		plaintext = pow(ciphertext, self.d, self.n)
		plaintext = self.int_to_bytes(plaintext)
		return plaintext

"""
In number theory, the Chinese remainder theorem states that 
if one knows the remainders of the Euclidean division of an integer n 
by several integers, then one can determine uniquely the remainder of the division of n 
by the product of these integers, under the condition that the divisors are pairwise coprime. 

# 2 = 23 % 3
# 3 = 23 % 5
# 2 = 23 % 7
n = [3, 5, 7]
a = [2, 3, 2]
chinese_remainder(n, a) == 23
"""

def main():
	rsa = RSA()
	rsa.gen_keypair()
	e1, n1 = rsa.get_public_key()
	rsa.gen_keypair()
	e2, n2 = rsa.get_public_key()
	rsa.gen_keypair()
	e3, n3 = rsa.get_public_key()

	ct1 = rsa.encrypt(3, n1)
	ct1 = int.from_bytes(ct1, 'big')
	ct2 = rsa.encrypt(3, n2)
	ct2 = int.from_bytes(ct2, 'big')
	ct3 = rsa.encrypt(3, n3)
	ct3 = int.from_bytes(ct3, 'big')

	n = [n1, n2, n3]
	a = [ct1, ct2, ct3]
	result_cubed = chinese_remainder(n, a)

	result = int(gmpy2.iroot_rem(result_cubed, 3)[0])

	plaintext = "%x" % result
	plaintext = bytes.fromhex(plaintext)
	plaintext = plaintext.decode('utf-8')
	print('recovered   :{}'.format(plaintext))	

if __name__ == '__main__':
	main()
