#!/usr/bin/python2
# -*- coding: utf-8 -*-

import string

fh = open('4.txt', 'r')
strings = fh.read().split()
fh.close()

candidatos = []
for s in strings:

	plaintexts = []
	for k in xrange(0xff + 1):
		r = ''
		for b in s.decode('hex'):
			r += chr( ord(b) ^ k )
		plaintexts.append(r)

	for pt in plaintexts:
		valid = True
		puntos = 0
		for c in pt:
			if c not in string.printable or c in ['\n', '\t', '\r', '\x0b', '\x0c']:
				valid = False
				break
			elif c == ' ':
				puntos += 2
			elif c in string.ascii_letters:
				puntos += 1
		if valid:
			candidatos.append([puntos, pt])


if len(candidatos) > 0:
	candidatos = sorted(candidatos, key=lambda elem: elem[0])
	for a, b in candidatos:
		print a, b
