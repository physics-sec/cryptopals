#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

def CBC_MAC(msg, key, iv):
	return encrypt_AES_CBC(msg, key, iv)[-16:]

def verify_signature(key, msg, iv, mac):
	return mac == CBC_MAC(msg, key, iv)

# This just returns the second to last ciphertext block xored with the last plaintext block
def last_intermediate(plaintext, key, iv):
	n = 16
	assert len(key) == n
	assert len(iv) == n
	plaintext = pad(plaintext)

	blocks = [plaintext[i:i+n] for i in range(0, len(plaintext), n)]
	ct = b''
	previus_block = iv
	blocks_len = len(blocks)

	block_num = 0
	for block in blocks:
		block_num += 1
		block_x = xor(block, previus_block)
		if block_num == blocks_len:
			return block_x
		block_en = encrypt_AES_ECB(block_x, key)
		previus_block = block_en
		ct += block_en
	return ct

def get_evil_js(code, evil_code, key, iv,):

	normal_intermediate = last_intermediate(code, key, iv)

	evil_js  = evil_code
	evil_js += b'//'
	evil_js += b' ' * (16 - (len(evil_js) % 16))

	# get second to last block
	while True:
		second_to_last_pt_block  = random_string(16).encode('utf-8')
		intermediate = last_intermediate(evil_js + second_to_last_pt_block, key, iv)
		AES_padding = b'\x10' * 16
		second_to_last_ct = xor(intermediate, AES_padding)
		if second_to_last_ct[-1] ^ 1 == normal_intermediate[-1]:
			break

	evil_js += second_to_last_pt_block

	evil_js += xor(normal_intermediate[:-1], second_to_last_ct[:-1])

	return evil_js

def main():
	key = rand_bytes(16)
	iv  = rand_bytes(16)
	code = b"alert('MZA who was that?');\n"
	evil_js = b"alert('Ayo, the Wu is back!');"

	evil_js = get_evil_js(code, evil_js, key, iv)
	new_mac = CBC_MAC(evil_js, key, iv)
	mac = CBC_MAC(code, key, iv)

	assert new_mac == mac
	print('original mac:{}'.format(mac.hex()))
	print(evil_js)
	print('new mac     :{}'.format(new_mac.hex()))

if __name__ == '__main__':
	main()
