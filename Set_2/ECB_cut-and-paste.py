#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
from Crypto.Cipher import AES

key = os.urandom(16)

def pad(s, pad_len=16):
	s_len = len(s)
	resto = s_len % pad_len
	b_len = pad_len - resto
	pad = bytes([ b_len ]) * b_len
	return s + pad

def unpad(s):
	return s[:-s[-1]]

def encrypt_AES_ECB(plaintext):
	assert len(key) == 128/8
	plaintext = pad(plaintext)
	assert len(plaintext) % 16 == 0
	cipher = AES.new(key, AES.MODE_ECB)
	ct = cipher.encrypt(plaintext)
	return ct

def decrypt_AES_ECB(ciphertext):
	assert len(key) == 128/8
	assert len(ciphertext) % 16 == 0
	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = cipher.decrypt(ciphertext)
	plaintext = unpad(plaintext)
	return plaintext

def s_to_obj(s):
	obj = {}
	for keyvalue in s.split(b'&'):
		key, value = keyvalue.split(b'=')
		obj[key] = value
	return obj

def obj_to_s(o):
	s = b''
	for key in o:
		s += key + b'=' + o[key] + b'&'
	return s[:-1]

def profile_for(mail):
	mail = mail.replace(b'&', b'').replace(b'=', b'')
	obj = {}
	obj[b'email'] = mail
	obj[b'uid']   = b'10'
	obj[b'role']  = b'user'
	s = obj_to_s(obj)
	return encrypt_AES_ECB(s)

def decrypt_and_parse(ct):
	pt = decrypt_AES_ECB(ct)
	return s_to_obj(pt)

def get_challenge_info():
	n = 16
	iguales_prev = 0
	for i in range(0, 16 + 1):
		test1 = b'_' * i + b'A'
		test2 = b'_' * i + b'B'
		result1 = profile_for( test1 )
		result1 = [result1[i:i+n] for i in range(0, len(result1), n)]
		result2 = profile_for( test2 )
		result2 = [result2[i:i+n] for i in range(0, len(result2), n)]
		iguales = 0
		for j in range(1, len(result1)):
			if result1[-j] == result2[-j]:
				iguales += 1
			else:
				break
		if iguales < iguales_prev:
			num_secret_blocks = iguales + 1
			padding = b'_' * i
			break
		else:
			iguales_prev = iguales

	ct_padding = profile_for(padding)
	len_padding = len(ct_padding)
	i = 0
	len_new = 0
	while len_new <= len_padding:
		i += 1
		ct_new = profile_for( padding + b'A' * i )
		len_new = len(ct_new)

	bs = len_new - len_padding

	num_blocks = int( len(ct_padding) / bs )
	offset_blocks = num_blocks - num_secret_blocks

	following_size  = bs * num_secret_blocks - i

	return [padding, following_size, offset_blocks]

"""
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ |
e m a i l = A A A A A A A A A A   a d m i n (11 de padding)         ...

_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ |
e m a i l = A A A A A A A A A A   A A A & u i d = 1 0 & r o l e =   a d m i n (11 de padding)

"""

def get_admin():
	padding, following_size, offset_blocks = get_challenge_info()
	mail  = padding
	mail += b'admin'
	pad_len = 16 - len(b'admin')
	mail += bytes( [pad_len] ) * pad_len
	ct = profile_for(mail)
	admin_block = ct[offset_blocks*16:(offset_blocks+1)*16]

	following_size = following_size - len(b'user')
	mail = padding + b'A' * (16 - (following_size % 16))
	ct = profile_for(mail)
	ct = ct[:-16] + admin_block
	o = decrypt_and_parse(ct)
	print(o)

if __name__ == '__main__':
	get_admin()
