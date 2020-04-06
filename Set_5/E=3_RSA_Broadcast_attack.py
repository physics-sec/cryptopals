#!/usr/bin/python3
# -*- coding: utf-8 -*-

import gmpy2

import sys
sys.path.append("..")
from cryptolib import *

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
	secret_plaintext = random_string(100).encode('utf-8')
	print('plaintext is:{}'.format(secret_plaintext.decode('utf-8')))

	rsa = RSA()
	rsa.gen_keypair()
	e1, n1 = rsa.get_public_key()
	rsa.gen_keypair()
	e2, n2 = rsa.get_public_key()
	rsa.gen_keypair()
	e3, n3 = rsa.get_public_key()

	ct1 = rsa.encrypt(secret_plaintext, 3, n1)
	ct1 = int.from_bytes(ct1, 'big')
	ct2 = rsa.encrypt(secret_plaintext, 3, n2)
	ct2 = int.from_bytes(ct2, 'big')
	ct3 = rsa.encrypt(secret_plaintext, 3, n3)
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
