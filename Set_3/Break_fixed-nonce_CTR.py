#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import struct
import base64
from Crypto.Cipher import AES

def rand_bytes(len):
	return os.urandom(len)

AES_key = rand_bytes(16)
nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

def xor(x1, x2):
    assert len(x1) == len(x2)
    b_list = list(map(lambda x,y: x^y, x1, x2))
    return bytes( b_list )

def encrypt_AES_ECB(AES_key, plaintext):
	assert len(AES_key) == 128/8
	cipher = AES.new(AES_key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def CTR(msg):
	n = 16
	ciphertext = b''
	for count in range( len(msg)//n ):
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(AES_key, plaintext)
		ciphertext += xor(ct, msg[n*count:n*(count+1)])

	msg_len = len(msg)
	if msg_len % n != 0:
		count += 1
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(AES_key, plaintext)
		ciphertext += xor(ct[:msg_len % n], msg[n*count:])
	return ciphertext

def main():
	pts_b64 = """SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="""

	pts = []
	cts = []
	max_pt_len = 0
	for p in pts_b64.split('\n'):
		pt = base64.b64decode(p)
		pt_len = len(pt)
		if pt_len > max_pt_len:
			max_pt_len = pt_len
		ct = CTR(pt)
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

	frec_english = [' ', 'E','T','A','O','I','N','S','R','H','D','L','U','C','M','F','Y','W','G','P','B','V','K','X','Q','J','Z', '.', ',']
	# reduced on porpuse
	printable = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\',-.:;? '
	printable_frist = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

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
