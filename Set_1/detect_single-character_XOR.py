#!/usr/bin/python3
# -*- coding: utf-8 -*-

import string

fh = open('4.txt', 'r')
strings = fh.read().split()
fh.close()

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

for candidato in strings:
	ct = bytes.fromhex(candidato)
	r = find_single_byte_xor(ct)
	if len(r) > 0:
		print(r[0])
