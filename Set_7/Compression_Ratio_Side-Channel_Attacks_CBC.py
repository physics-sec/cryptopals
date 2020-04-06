#!/usr/bin/python3
# -*- coding: utf-8 -*-

import zlib
import sys
sys.path.append("..")
from cryptolib import *

key = rand_bytes(16)
cookie = ''

def format_req(P):
	return """POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid={}
Content-Length: {:d}

{}""".format(cookie, len(P), P).encode('utf-8')

def oracle(P):
	req = format_req(P)
	compressed_data = zlib.compress(req, 2)
	encrypted = encrypt_AES_CBC(compressed_data, key, rand_bytes(16))
	length = len(encrypted)
	return length

def find_cookie():
	global cookie
	chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
	cookie = ''.join(random.choice(chars) for i in range(random.randint(40, 50)))
	print(cookie)
	cookielen = len(cookie)
	leaked = ''
	prepend = ''
	while len(leaked) < cookielen:
		char_length = {}
		min_size = None
		max_size = None
		for c1 in chars:
			for c2 in chars:
				if len(leaked) == cookielen - 1:
					if c2 != 'a':
						continue
					c2 = ''
				cookie_test = leaked + c1 + c2
				length = oracle('{}Cookie: sessionid={}'.format(prepend, cookie_test))
				char_length[c1 + c2] = length
				if min_size is None:
					min_size = length
				if max_size is None:
					max_size = length
				if length > max_size:
					max_size = length
					break
				if length < min_size:
					min_size = length
					break
			else:
				continue
			break
		if max_size == min_size:
			prepend += chars[len(prepend) % len(chars)]
			print('prepend:{}'.format(prepend))
			leaked = ''
		else:
			sorted_chars = sorted(char_length, key=lambda elem: char_length[elem])
			new_char = sorted_chars[0]
			leaked += new_char
			print(leaked)
	if leaked == cookie:
		print('leaked cookie:{}'.format(leaked))
	else:
		print('Fail!')
		print('Cookie was:{}'.format(cookie))
		print('And got   :{}'.format(leaked))
		return

if __name__ == '__main__':
	try:
		find_cookie()
	except KeyboardInterrupt:
		pass
