#!/usr/bin/python3
# -*- coding: utf-8 -*-

import string
import random
import base64
import struct
import hashlib
import subprocess
import collections
from functools import reduce
from Crypto.Cipher import AES

def rand_bytes(length):
	return bytes(random.getrandbits(8) for _ in range(length))

def unpad(s):
	if len(s) % 16 != 0:
		raise Exception('Bad Padding')
	pad_len = s[-1]
	if pad_len > 16 or pad_len < 1:
		raise Exception('Bad Padding')
	for i in range(1, pad_len + 1):
		if s[-i] != pad_len:
			raise Exception('Bad Padding')
	return s[:-s[-i]]

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

def decrypt_AES_ECB(data, key):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	pt = cipher.decrypt(data)
	return pt

def encrypt_AES_ECB(plaintext, key):
	assert len(key) == 16
	cipher = AES.new(key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def encrypt_AES_CBC(plaintext, key, iv, n=16, do_padding=True):
	assert len(key) == n
	assert len(iv) == n
	if do_padding:
		plaintext = pad(plaintext)

	blocks = [plaintext[i:i+n] for i in range(0, len(plaintext), n)]
	ct = b''
	previus_block = iv

	for block in blocks:
		block_x = xor(block, previus_block)
		block_en = encrypt_AES_ECB(block_x, key)
		previus_block = block_en
		ct += block_en
	return ct

def decrypt_AES_CBC(ciphertext, key, iv, n=16, do_unpadding=True):
	assert len(key) == n
	assert len(iv) == n
	ciphertext_len = len(ciphertext)
	assert ciphertext_len % n == 0

	blocks = [ciphertext[i:i+n] for i in range(0, ciphertext_len, n)]
	pt = []
	previus_block = iv

	for block in blocks:
		d_block = decrypt_AES_ECB(block, key)
		pt_block = xor(d_block, previus_block)
		pt.append(pt_block)
		previus_block = block
	if do_unpadding:
		return unpad(b''.join(pt))
	else:
		return b''.join(pt)

def hamming_distance(s1, s2):
	assert len(s1) == len(s2)

	diff_bits = 0
	for i in range(len(s1)):
		b1 = ord(s1[i])
		b2 = ord(s2[i])
		x = b1 ^ b2
		for i in range(8):
			if x & (2 ** i):
				diff_bits -=- 1

	return diff_bits

def CTR(msg, key, nonce, n=16):
	ciphertext = b''
	for count in range( len(msg)//n ):
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(plaintext, key)
		ciphertext += xor(ct, msg[n*count:n*(count+1)])

	msg_len = len(msg)
	if msg_len % n != 0:
		count += 1
		counter = struct.pack("<Q", count)
		plaintext = nonce + counter
		ct = encrypt_AES_ECB(plaintext, key)
		ciphertext += xor(ct[:msg_len % n], msg[n*count:])
	return ciphertext

def random_string(length):
	return ''.join(random.choice(string.ascii_lowercase) for i in range(length))

def mul_inv(a, b):
	b0 = b
	x0, x1 = 0, 1
	if b == 1: return 1
	while a > 1:
		q = a // b
		a, b = b, a%b
		x0, x1 = x1 - q * x0, x0
	if x1 < 0: x1 += b0
	return x1

def chinese_remainder(n, a):
	sum = 0
	prod = reduce(lambda a, b: a*b, n)
	for n_i, a_i in zip(n, a):
		p = prod // n_i
		sum += a_i * mul_inv(p, n_i) * p
	return sum % prod

class RSA():

	def gen_prime(self, prime_size):
		process = subprocess.Popen(['openssl', 'prime', '-generate', '-bits', str(prime_size), '-hex'], stdout=subprocess.PIPE)
		prime = process.communicate()[0][:-1]
		prime = int(prime.decode('utf-8'), 16	)
		return prime

	def gen_keypair(self, prime_size=512):
		p = self.gen_prime(prime_size)
		q = self.gen_prime(prime_size)
		if p == q:
			return self.gen_keypair()
		self.n = p * q
		et = (p - 1) * (q - 1)
		self.e = 3
		self.d = invmod(self.e, et)

	def get_public_key(self):
		return [self.e, self.n]

	def get_private_key(self):
		return [self.d, self.n]

	def encrypt(self, plaintext, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		plaintext = bytes_to_int(plaintext)
		if plaintext > n:
			raise Exception('plaintext is longer than n')
		ciphertext = pow(plaintext, e, n)
		ciphertext = int_to_bytes(ciphertext)
		return ciphertext

	def encrypt_PKCS(self, D, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		k = len(int_to_bytes(n))

		len_D = len(D)
		assert len_D <= k - 11

		PS = b''
		for i in range(k - 3 - len_D):
			PS += bytes( [random.randint(1,255)] )

		EB = b'\x00\x02' + PS + b'\x00' + D
		EB = bytes_to_int(EB)

		ciphertext = pow(EB, e, n)
		ciphertext = int_to_bytes(ciphertext)
		return ciphertext

	def decrypt(self, ciphertext):
		ciphertext = bytes_to_int(ciphertext)
		#if ciphertext > self.n:
		#	raise Exception('ciphertext is longer than n')
		plaintext = pow(ciphertext, self.d, self.n)
		plaintext = int_to_bytes(plaintext)
		return plaintext

	def decrypt_PKCS(self, ciphertext):
		k = len(int_to_bytes(self.n))
		ciphertext = bytes_to_int(ciphertext)

		EB = pow(ciphertext, self.d, self.n)
		EB = int_to_bytes(EB, k)

		if EB[:2] != b'\x00\x02':
			raise Exception('Bad padding')

		EB = EB[2:]

		if b'\x00' not in EB:
			raise Exception('Bad padding')

		null_index = EB.find(b'\x00')
		PS = EB[ : null_index ]

		EB = EB[ null_index + 1 : ]
		plaintext = EB

		return plaintext

	def verify(self, signature, message, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		k = len(int_to_bytes(self.n))

		signature = bytes_to_int(signature)
		message_obtained = pow(signature, e, n)
		message_obtained = int_to_bytes(message_obtained, k)

		try:
			assert message_obtained[:2] == b'\x00\x01'

			h = hashlib.sha256()
			h.update(message)
			digest = h.digest()

			# https://crypto.stackexchange.com/questions/30183/how-do-you-communicate-the-hash-function-used-with-rsa-signing
			# https://www.ibm.com/developerworks/community/forums/html/topic?id=5e85561a-e225-400a-ba5c-b3d29e4f9ab0
			# https://stackoverflow.com/questions/3713774/c-sharp-how-to-calculate-asn-1-der-encoding-of-a-particular-hash-algorithm
			ASNSHA256 = b"\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

			asn_digest = message_obtained.split(b'\xff\x00')[1]

			assert ASNSHA256 == asn_digest[:len(ASNSHA256)]
			digest_size = asn_digest[18]
			digest_msg = asn_digest[len(ASNSHA256): len(ASNSHA256) + digest_size ]

			return digest_msg == digest
		except AssertionError:
			return False

	def sign(self, message):
		k = len(int_to_bytes(self.n))

		h = hashlib.sha256()
		h.update(message)
		digest = h.digest()

		# https://crypto.stackexchange.com/questions/30183/how-do-you-communicate-the-hash-function-used-with-rsa-signing
		# https://www.ibm.com/developerworks/community/forums/html/topic?id=5e85561a-e225-400a-ba5c-b3d29e4f9ab0
		ASNSHA256 = b"\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

		padding = b''
		for i in range(k - len(ASNSHA256) - 3 - len(digest)):
			padding += b'\xff'

		block = b'\x00\x01' + padding + b'\x00' + ASNSHA256 + digest

		block = bytes_to_int(block)
		if block > self.n:
			raise Exception('block is longer than n')
		signature = pow(block, self.d, self.n)
		signature = int_to_bytes(signature)
		return signature

	def oracle(self, ciphertext):
		k = len(int_to_bytes(self.n))
		ciphertext = bytes_to_int(ciphertext)

		EB = pow(ciphertext, self.d, self.n)
		EB = int_to_bytes(EB, k)

		if EB[:2] != b'\x00\x02':
			return False

		# acoording to the paper, no further checks are made
		return True

		EB = EB[2:]

		if b'\x00' not in EB:
			return False

		null_index = EB.find(b'\x00')
		PS = EB[ : null_index ]

		EB = EB[ null_index + 1 : ]
		plaintext = EB

		return True

class DSA():

	def __init__(self, \
		p=0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1, \
		q=0xf4f47f05794b256174bba6e9b396a7707e563c5b, \
		g=0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291, \
		prime_size=512):
		self.p = p
		self.q = q
		self.g = g

	def gen_keypair(self):
		self.x = random.randint(1, self.q - 1)
		self.y = pow(self.g, self.x, self.p)

	def sign(self, message, x=None, k=None):
		if x is None:
			x = self.x
		if k is None:
			k = random.randint(1, self.q - 1)

		r = pow(self.g, k, self.p) % self.q
		#if r == 0:
		#	return self.sign(message, x, k)
		inv_k = invmod(k, self.q)
		sha1 = hashlib.sha1()
		sha1.update(message)
		dig = sha1.digest()
		h_m = bytes_to_int(dig)
		s = (inv_k * ( h_m + x * r )) % self.q
		#if s == 0:
		#	return self.sign(message, x, k)
		return (int_to_bytes(r), int_to_bytes(s))

	def verify(self, r, s, message):
		r = bytes_to_int(r)
		s = bytes_to_int(s)
		#assert r > 0 and r < self.q and s > 0 and s < self.q
		w = invmod(s, self.q)
		sha1 = hashlib.sha1()
		sha1.update(message)
		dig = sha1.digest()
		h_m = bytes_to_int(dig)
		u1  = h_m * w % self.q
		u2  = r * w % self.q
		v   = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
		return v == r

def index_of_coincidence(data):
	data_len = len(data)
	d = data_len * (data_len - 1)
	frec = collections.Counter()
	for b in data:
		frec[b] += 1
	ic = 0
	for b in frec:
		ic += (frec[b] * (frec[b] - 1)) / d
	return ic

def int_to_bytes(integer, size=None):
	hex_string = "%x" % integer
	if len(hex_string) % 2 == 1:
		hex_string = '0' + hex_string
	if size and len(hex_string) // 2 < size:
		nullbytes = '00' * (size - len(hex_string) // 2)
		hex_string = nullbytes  + hex_string
	return bytes.fromhex(hex_string)

def bytes_to_int(byte_arr, endianness='big'):
	return int.from_bytes(byte_arr, endianness)

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def invmod(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m
