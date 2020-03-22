#!/usr/bin/python3
# -*- coding: utf-8 -*-

def pad(s, pad_len):
	s_len = len(s)
	resto = s_len % pad_len
	b_len = pad_len - resto
	pad = bytes([ b_len ]) * b_len
	return s + pad

print(pad(b"YELLOW SUBMARINE", 20))
print(pad(b"YELLOW SUBMARINE", 10))
