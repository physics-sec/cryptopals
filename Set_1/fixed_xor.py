#!/usr/bin/python
# -*- coding: utf-8 -*-

x1 = '1c0111001f010100061a024b53535009181c'.decode('hex')

x2 = '686974207468652062756c6c277320657965'.decode('hex')

assert len(x1) == len(x2)

r = ''
for i in xrange(len(x1)):
	r += chr( ord(x1[i]) ^ ord(x2[i]) )

r = r.encode('hex')

print r


