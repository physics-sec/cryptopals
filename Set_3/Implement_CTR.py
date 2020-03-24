#!/usr/bin/python3
# -*- coding: utf-8 -*-

import struct
import base64
from Crypto.Cipher import AES

def xor(x1, x2):
	assert len(x1) == len(x2)
	r = b''
	for i in range(len(x1)):
		r += bytes([ x1[i] ^ x2[i] ])
	return r

def encrypt_AES_ECB(key, plaintext):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def CTR(key, nonce, msg):
	n = 16
	ciphertext = b''
	for count in range( len(msg)//n ):
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(key, plaintext)
		ciphertext += xor(ct, msg[n*count:n*(count+1)])
	return ciphertext

def main():
	msg = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	msg = base64.b64decode(msg)

	key = b'YELLOW SUBMARINE'

	nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

	pt = CTR(key, nonce, msg)

	print(pt)

if __name__ == '__main__':
	main()
