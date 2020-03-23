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

"""
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ |
e m a i l = A A A A A A A A A A   a d m i n (11 de padding)         ...

_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ |
e m a i l = A A A A A A A A A A   A A A & u i d = 1 0 & r o l e =   a d m i n (11 de padding)

"""

def get_admin():
	mail  = b'A' * 10
	mail += b'admin'
	mail += bytes([11]) * 11
	ct = profile_for(mail)
	admin_block = ct[16:16*2]

	mail = b'A' * 13
	ct = profile_for(mail)
	ct = ct[:16*2] + admin_block
	o = decrypt_and_parse(ct)
	print(o)

if __name__ == '__main__':
	get_admin()
