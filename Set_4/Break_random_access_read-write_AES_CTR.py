#!/usr/bin/python3
# -*- coding: utf-8 -*-

import struct
import base64
import os
from Crypto.Cipher import AES

key = os.urandom(16)
nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

def xor(x1, x2):
    assert len(x1) == len(x2)
    b_list = list(map(lambda x,y: x^y, x1, x2))
    return bytes( b_list )

def encrypt_AES_ECB(key, plaintext):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def CTR(key, nonce, msg):
	msg_len = len(msg)
	assert len(nonce) == 8
	n = 16
	count = -1
	ciphertext = b''
	for count in range( msg_len//n ):
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(key, plaintext)
		ciphertext += xor(ct, msg[n*count:n*(count+1)])

	if msg_len % n != 0:
		count += 1
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(key, plaintext)
		ciphertext += xor(ct[:msg_len % n], msg[n*count:])
	return ciphertext

def edit(ciphertext, offset, newtext):
	pad = b'\x00' * offset
	newct = CTR(key, nonce, pad + newtext)
	newct = ciphertext[:offset] + newct[offset:offset+len(newtext)] + ciphertext[offset+len(newtext):]
	return newct

def get_ct():
	fh = open('plaintext.b64', 'r')
	data = fh.read()
	data = base64.b64decode(data)
	fh.close()

	ct = CTR(key, nonce, data)
	return ct

def main():
	ct = get_ct()

	pt = b'\x00' * len(ct)

	new_ct = edit(ct, 0, pt)

	keystream = xor(new_ct, pt)

	pt = xor(ct, keystream)

	print(pt)

if __name__ == '__main__':
	main()
