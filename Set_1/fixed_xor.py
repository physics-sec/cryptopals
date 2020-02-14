#!/usr/bin/python3
# -*- coding: utf-8 -*-

import codecs

def xor(x1, x2):
	assert len(x1) == len(x2)
	r = b''
	for i in range(len(x1)):
		r += bytes([ ord(x1[i]) ^ ord(x2[i]) ])
	return codecs.encode(r, 'hex')

x1 = bytes.fromhex('1c0111001f010100061a024b53535009181c').decode('utf-8')
x2 = bytes.fromhex('686974207468652062756c6c277320657965').decode('utf-8')

r = xor(x1, x2)

print(r)
