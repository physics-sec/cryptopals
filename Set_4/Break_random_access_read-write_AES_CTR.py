#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

key = rand_bytes(16)
nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

def edit(ciphertext, offset, newtext):
	pad = b'\x00' * offset
	newct = CTR(pad + newtext, key, nonce)
	newct = ciphertext[:offset] + newct[offset:offset+len(newtext)] + ciphertext[offset+len(newtext):]
	return newct

def get_ct():
	fh = open('plaintext.b64', 'r')
	data = fh.read()
	data = base64.b64decode(data)
	fh.close()

	ct = CTR(data, key, nonce)
	return ct

def main():
	ct = get_ct()

	pt = b'\x00' * len(ct)

	new_ct = edit(ct, 0, pt)

	keystream = xor(new_ct, pt)

	pt = xor(ct, keystream)

	print(pt.decode('utf-8'))

if __name__ == '__main__':
	main()
