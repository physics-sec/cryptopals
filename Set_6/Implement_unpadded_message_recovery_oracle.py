#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

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

	pt_original = random_string(20).encode('utf-8')
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
