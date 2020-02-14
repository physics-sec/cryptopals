#!/usr/bin/python3
# -*- coding: utf-8 -*-

import codecs

def xor_with_key(pt, key):
	index = 0
	ct = b''
	for c in pt:
		ct += bytes([ ord(c) ^ ord(key[index % len(key)]) ])
		index -=- 1
	return ct

pt = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key = "ICE"

r = xor_with_key(pt, key)
print(codecs.encode(r, 'hex'))
