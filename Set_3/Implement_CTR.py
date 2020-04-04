#!/usr/bin/python3
# -*- coding: utf-8 -*-

import struct
import base64
from Crypto.Cipher import AES

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

def main():
	msg = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	msg = base64.b64decode(msg)

	key = b'YELLOW SUBMARINE'

	nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

	pt = CTR(key, nonce, msg)

	print(pt)

if __name__ == '__main__':
	main()
