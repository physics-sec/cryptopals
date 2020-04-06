#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

def s_is_valid(c, s, e, n, rsa):
	ct = (c * pow(s, e)) % n
	ct = int_to_bytes(ct)
	return rsa.oracle(ct)

def ceil(a, b):
	add = 0
	if a % b != 0:
		add = 1
	return (a // b) + add

def floor(a, b):
	return a // b

def main():
	# http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
	rsa = RSA()
	rsa.gen_keypair(prime_size=384)
	e, n = rsa.get_public_key()
	msg = b'kick it, CC'
	c = rsa.encrypt_PKCS(msg)
	c = bytes_to_int(c)
	k = len(int_to_bytes(n))
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
				r = 2 * floor(b*s - 2*B, n)
				while True:
					s_min = floor(2*B + r*n, b)
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
		M_prev = M
		M = []
		for a, b in M_prev:
			r_min = floor(a*s - 3*B + 1, n)
			r_max = ceil(b*s - 2*B, n)
			for r in range(r_min, r_max + 1):
				new_a = max(a, ceil((2*B+r*n), s))
				new_b = min(b, floor(3*B-1+r*n, s))
				if new_a <= new_b:
					M.append( [new_a, new_b] )

		for a, b in M:
			print('b - a:{:d}'.format(b - a))
			if a == b:
				print('message:')
				msg_bytes = int_to_bytes(a)
				print(msg_bytes)
				index = msg_bytes.find(b'\x00')
				print(msg_bytes[index+1:])
				return

		if len(M) == 0:
			exit('M == []')

if __name__ == '__main__':
	main()
