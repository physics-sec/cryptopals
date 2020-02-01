#!/usr/bin/python2
# -*- coding: utf-8 -*-


pt = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

key = "ICE"

ct = ''

index = 0
for c in pt:
	ct += chr( ord(c) ^ ord(key[index % 3]) )
	index -=- 1

print ct.encode('hex')
