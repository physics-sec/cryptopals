#!/usr/bin/python2
# -*- coding: utf-8 -*-

import string
s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

results = []
for k in xrange(0xff + 1):
	r = ''
	for b in s.decode('hex'):
		r += chr( ord(b) ^ k )
	results.append(r)

final = []
for rel in results:
	valid = True
	puntos = 0
	for c in rel:
		if c not in string.printable or c in ['\n', '\t', '\r', '\x0b', '\x0c']:
			valid = False
			break
		if c in string.ascii_letters:
			puntos += 1
	if valid:
		final.append([puntos, rel])

for p, rel in final:
	print p, rel
