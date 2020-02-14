#!/usr/bin/python3
# -*- coding: utf-8 -*-

import string

ct = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')

def find_single_byte_xor(ct):
	frec = {}

	for b in ct:
		if b not in frec:
			frec[b] = 1
		else:
			frec[b] += 1

	frec = sorted(frec, key=lambda elem: -frec[elem])

	resp = []
	for b in frec:
		# space is likely the most common char in plain text
		key = ord(' ') ^ b
		r = b''
		valid = True
		for i in range(len(ct)):
			c = bytes([ ct[i] ^ key ])
			if c not in bytes(string.printable, 'ascii'):
				valid = False
				break
			r += c
		if valid is False:
			continue
		r = str(r,'ascii')
		resp.append(r)
	return resp

print(find_single_byte_xor(ct)[0])
