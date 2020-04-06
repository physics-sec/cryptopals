#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

AES_key = rand_bytes(16)
nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

def main():
	fh = open('20.txt')
	pts_b64 = fh.read()
	fh.close()

	pts = []
	cts = []
	max_pt_len = 0
	for p in pts_b64.split('\n'):
		pt = base64.b64decode(p)
		pt_len = len(pt)
		if pt_len > max_pt_len:
			max_pt_len = pt_len
		ct = CTR(pt, AES_key, nonce)
		cts.append(ct)

	# get real key for testing
	k = ''
	for count in range(max_pt_len  // 16 + 1):
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(AES_key, plaintext)
		k += ct.hex()
	k = k[:max_pt_len*2]

	# each block has the same AES_key
	# and each pos is xor with the same AES_key byte

	frec_english = [' ', 'E','T','A','O','I','N','S','R','H','D','L','U','C','M','F','Y','W','G','P','B','V','K','X','Q','J','Z', '.', ',', '-', '/', ':', ';','?', '\'', '"', '4', '!']
	# reduced on porpuse
	printable = '"4abcdefghijklmnopqrstuvwxyzABCDEFHIJKLMNOPRSTWYZ!\',-./:;? '
	printable_frist = '\'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

	for char in printable:
		if char not in frec_english:
			frec_english.append(char)

	derived_key = {}
	for pos in range(max_pt_len):

		derived_key[pos] = []

		frec = {}
		for ct in cts:
			if pos >= len(ct):
				continue

			b = ct[pos]
			if b not in frec:
				frec[b]  = 1
			else:
				frec[b] += 1

		frec = sorted(frec, key=lambda elem: frec[elem], reverse=True)

		for b in frec:
			for char in frec_english:
				if pos == 0:
					char = char.upper()
					if char == ' ':
						continue
				else:
					char = char.lower()

				key_byte = b ^ ord(char)

				for ct in cts:
					if pos == 0:
						allowed = printable_frist
					else:
						allowed = printable
					if pos < len(ct) and chr( ct[pos] ^ key_byte ) not in allowed:
						break
				else:
					byte_derived = bytes([key_byte]).hex()
					if byte_derived not in derived_key[pos]:
						derived_key[pos].append(byte_derived)


	recovered_key = b''
	for pos in derived_key:
		correct_byte = k[pos*2:pos*2+2]

		if correct_byte not in derived_key[pos]:
			print('Failed to recover key byte {:d}\n'.format(pos))
		elif correct_byte != derived_key[pos][0]:
			ind = derived_key[pos].index(correct_byte)
			print('Falied to guess the correct key byte {:d}'.format(pos))
			print('correct choise was in pos {:d}\n'.format(ind))
		elif len(recovered_key) == pos:
			recovered_key += bytes.fromhex(derived_key[pos][0])

	print('')
	print('Actual key key:{}'.format(k))
	print('Derived key   :{}'.format(recovered_key.hex()))
	print('Derived {:d} bytes of {:d}'.format(len(recovered_key), max_pt_len))
	print('')

	ks_len = len(recovered_key)
	for ct in cts:
		ct_len = len(ct)
		xor_key = recovered_key
		if ct_len > ks_len:
			ct = ct[:ks_len]
		elif ct_len < ks_len:
			xor_key = recovered_key[:ct_len]
		pt = xor(xor_key, ct)
		if pt:
			print(pt)

if __name__ == '__main__':
	main()
