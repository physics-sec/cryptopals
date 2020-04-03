#!/usr/bin/python3
# -*- coding: utf-8 -*-

import math
import random
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
		prime_size = 384
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
		return [self.e, self.n]

	def get_private_key(self):
		return [self.d, self.n]

	def int_to_bytes(self, integer, size=None):
		hex_string = "%x" % integer
		if len(hex_string) % 2 == 1:
			hex_string = '0' + hex_string
		if size and len(hex_string) // 2 < size:
			nullbytes = '00' * (size - len(hex_string) // 2)
			hex_string = nullbytes  + hex_string
		return bytes.fromhex(hex_string)

	def bytes_to_int(self, byte_arr):
		return int.from_bytes(byte_arr, 'big')

	def encrypt(self, D, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		k = len(self.int_to_bytes(n))

		len_D = len(D)
		assert len_D <= k - 11

		PS = b''
		for i in range(k - 3 - len_D):
			PS += bytes( [random.randint(1,255)] )

		EB = b'\x00\x02' + PS + b'\x00' + D
		EB = self.bytes_to_int(EB)

		ciphertext = pow(EB, e, n)
		ciphertext = self.int_to_bytes(ciphertext)
		return ciphertext, EB

	def oracle(self, ciphertext):
		k = len(self.int_to_bytes(self.n))
		ciphertext = self.bytes_to_int(ciphertext)

		EB = pow(ciphertext, self.d, self.n)
		EB = self.int_to_bytes(EB, k)

		if EB[:2] != b'\x00\x02':
			return False

		# acoording to the paper, no further checks are made
		return True

		EB = EB[2:]

		if b'\x00' not in EB:
			return False

		null_index = EB.find(b'\x00')
		PS = EB[ : null_index ]

		EB = EB[ null_index + 1 : ]
		plaintext = EB

		return True

def s_is_valid(c, s, e, n, rsa):
	ct = (c * pow(s, e)) % n
	ct = rsa.int_to_bytes(ct)
	return rsa.oracle(ct)

def ceil(a, b):
	add = 0
	if a % b != 0:
		add = 1
	return (a // b) + add

def main():
	# http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
	rsa = RSA()
	rsa.gen_keypair()
	e, n = rsa.get_public_key()
	msg = b'kick it, CC'
	c, m = rsa.encrypt(msg)
	c = rsa.bytes_to_int(c)
	k = len(rsa.int_to_bytes(n))
	B = pow(2, 8*(k-2))

	M = [ [2*B, 3*B - 1] ]

	i = 0
	while True:
		i += 1
		if i == 1:
			# Step 2.a
			s = ceil(n, 3*B)
			while True:
				if s_is_valid(c, s, e, n, rsa):
					break
				s += 1
		else:
			if len(M) == 1:
				# Step 2.c
				a, b = M[0]
				r = 2 * ((b*s - 2*B) // n)
				while True:
					s_min = (2*B + r*n) // b
					s_max = ceil(3*B + r*n, a)
					for s in range(s_min, s_max+1):
						if s_is_valid(c, s, e, n, rsa):
							break
					else:
						r += 1
						continue
					break
			else:
				# Step 2.b
				while True:
					s += 1
					if s_is_valid(c, s, e, n, rsa):
						break

		# Step 3
		actualR = (m * s) // n
		r_found = False
		M_prev = M
		M = []
		for a, b in M_prev:

			r_min = (a*s - 3*B + 1) // n
			r_max = ceil(b*s - 2*B, n)
			for r in range(r_min, r_max + 1):
				new_a = max(a, ceil((2*B+r*n), s))
				if b - a == 1:
					new_a = max(a, ceil((2*B+r*n), s))
				new_b = min(b, (3*B-1+r*n)//s)
				if new_a <= new_b:
					if new_a <= m and m <= new_b:
						if r == actualR:
							r_found = True
						M.append( [new_a, new_b] )

		m_found = False
		for a, b in M:
			print('b - a:{:d}'.format(b - a))
			if a == b:
				print('message:')
				msg_bytes = rsa.int_to_bytes(a)
				print(msg_bytes)
				index = msg_bytes.find(b'\x00')
				print(msg_bytes[index+1:])
				return
			if m >= a and m <= b:
				m_found = True
		if len(M) == 0:
			exit('M == []')
		if m_found is False:
			exit(f'm {m} not in any range')
		if r_found is False:
			exit(f'r {r} not in range')

if __name__ == '__main__':
	main()
