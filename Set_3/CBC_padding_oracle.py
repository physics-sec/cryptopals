#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import random
import base64
from Crypto.Cipher import AES

def rand_bytes(len):
	return os.urandom(len)

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

def unpad(s):
	return s[:-s[-1]]

def pad(s, pad_len=16):
	s_len = len(s)
	resto = s_len % pad_len
	b_len = pad_len - resto
	pad = bytes([ b_len ]) * b_len
	return s + pad

def xor(x1, x2): 
    assert len(x1) == len(x2) 
    b_list = list(map(lambda x,y: x^y, x1, x2)) 
    return bytes( b_list )

def encrypt_AES_ECB(plaintext):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def encrypt_AES_CBC(plaintext):
	n = 16
	assert len(key) == n
	iv = rand_bytes(16)
	assert len(iv) == n
	plaintext = pad(plaintext)

	blocks = [plaintext[i:i+n] for i in range(0, len(plaintext), n)]
	ct = b''
	previus_block = iv

	for block in blocks:
		block_x = xor(block, previus_block)
		block_en = encrypt_AES_ECB(block_x)
		previus_block = block_en
		ct += block_en
	return [ct, iv]

def decrypt_AES_ECB(data):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	pt = cipher.decrypt(data)
	return pt

def validate_padding(s):
	if len(s) % 16 != 0:
		return False
	pad_len = s[-1]
	if pad_len > 16 or pad_len < 1:
		return False
	for i in range(1, pad_len + 1):
		if s[-i] != pad_len:
			return False
	return True

def decrypt_AES_CBC(ciphertext, iv):
	n = 16
	assert len(key) == n
	assert len(iv) == n
	ciphertext_len = len(ciphertext)
	assert ciphertext_len % n == 0

	blocks = [ciphertext[i:i+n] for i in range(0, ciphertext_len, n)]
	pt = b''
	previus_block = iv

	for block in blocks:
		d_block = decrypt_AES_ECB(block)
		pt_block = xor(d_block, previus_block)
		pt += pt_block
		previus_block = block
	return validate_padding(pt)

def enc():
	data = s.split('\n')[random.randint(0, 9)]
	data = base64.b64decode(data)
	ct, iv = encrypt_AES_CBC(data)
	return [ct, iv]

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

			if decrypt_AES_CBC(ct, iv):
				# check for acidental 0x2 0x2 padding
				if leaked_len == 0:
					ct  = C1[:-1]
					ct += bytes( [C1[-1] ^ 1] ) # change second to last byte
					ct += bytes( [b] )
					ct += C2
					if decrypt_AES_CBC(ct, iv) is False:
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
