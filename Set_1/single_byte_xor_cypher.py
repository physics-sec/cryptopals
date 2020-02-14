#!/usr/bin/python3
# -*- coding: utf-8 -*-

import string

ct = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736').decode('utf-8')

def find_single_byte_xor(ct):
	frec = {}

	for b in ct:
		if str(b) not in frec:
			frec[str(b)] = 1
		else:
			frec[str(b)] += 1

	frec = sorted(frec, key=lambda elem: -frec[elem[0]])

	resp = []
	for b in frec:
		# space is likely the most common char in plain text
		key = ord(' ') ^ ord(b)
		r = b''
		for i in range(len(ct)):
			r += bytes([ ord(ct[i]) ^ key ])
		r = str(r,'ascii')
		valid = True
		for b in r:
			if b not in string.printable:
				valid = False
				break
		if valid:
			resp.append(r)
	return resp

print(find_single_byte_xor(ct)[0])
