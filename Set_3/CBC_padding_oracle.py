#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

s = """MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"""

key = rand_bytes(16)

def validate_padding(s):
	try:
		unpad(s)
		return True
	except Exception:
		return False

def enc():
	data = s.split('\n')[random.randint(0, 9)]
	data = base64.b64decode(data)
	iv = rand_bytes(16)
	ct = encrypt_AES_CBC(data, key, iv)
	return [ct, iv]

def check_padding(ciphertext, key, iv):
	pt = decrypt_AES_CBC(ciphertext, key, iv, do_unpadding=False)
	return validate_padding(pt)


def pad_oracle_attack(C1, C2, iv):
	# https://robertheaton.com/2013/07/29/padding-oracle-attack/

	C1_original = C1
	leaked = b''
	intermediates = b''

	for leaked_len in range(16):

		C1 = rand_bytes(16 - leaked_len - 1)
		pad = b''
		for i in range(1, leaked_len + 1):
			intermediate = intermediates[-i]
			new = intermediate ^ (leaked_len + 1)
			new = bytes( [new] )
			pad = new + pad

		for b in range(256):
			ct  = C1
			ct += bytes( [b] )
			ct += pad
			ct += C2

			if check_padding(ct, key, iv):
				# check for acidental 0x2 0x2 padding
				if leaked_len == 0:
					ct  = C1[:-1]
					ct += bytes( [C1[-1] ^ 1] ) # change second to last byte
					ct += bytes( [b] )
					ct += C2
					if check_padding(ct, key, iv) is False:
						continue # is was a 0x2 0x2 padding

				intermediate = b ^ (leaked_len + 1)
				intermediates = bytes( [intermediate] ) + intermediates
				original = C1_original[-leaked_len - 1]
				leak = intermediate ^ original
				leak = bytes([leak])
				leaked = leak + leaked
				#print(b'leaked:' + leaked)
				break
		else:
			exit('error: correct padding not found')
	return leaked

def decrypt():
	ct_original, iv = enc()
	ct_len = len(ct_original)
	n = 16
	blocks = [ct_original[i:i+n] for i in range(0, ct_len, n)]

	leak = b''
	for i in range(1, len(blocks)):
		leak += pad_oracle_attack(blocks[i-1], blocks[i], iv)

	first = pad_oracle_attack(iv, blocks[0], iv)

	leak = first + leak
	leak = unpad(leak)
	print(leak)

if __name__ == '__main__':
	decrypt()
