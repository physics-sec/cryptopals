#!/usr/bin/python3
# -*- coding: utf-8 -*-

import io
import os
import struct
import random
import base64
import string
from Crypto.Cipher import AES

def rand_bytes(len):
	return os.urandom(len)

class Sha1Hash(object):
	"""A class that mimics that hashlib api and implements the SHA-1 algorithm."""

	name = 'python-sha1'
	digest_size = 20
	block_size = 64

	def __init__(self):
		# Initial digest variables
		self._h = (
			0x67452301,
			0xEFCDAB89,
			0x98BADCFE,
			0x10325476,
			0xC3D2E1F0,
		)

		# bytes object with 0 <= len < 64 used to store the end of the message
		# if the message length is not congruent to 64
		self._unprocessed = b''
		# Length in bytes of all data that has been processed so far
		self._message_byte_length = 0

	def _left_rotate(self, n, b):
		"""Left rotate a 32-bit integer n by b bits."""
		return ((n << b) | (n >> (32 - b))) & 0xffffffff


	def _process_chunk(self, chunk, h0, h1, h2, h3, h4):
		"""Process a chunk of data and return the new digest variables."""
		assert len(chunk) == 64

		w = [0] * 80

		# Break chunk into sixteen 4-byte big-endian words w[i]
		for i in range(16):
			w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

		# Extend the sixteen 4-byte words into eighty 4-byte words
		for i in range(16, 80):
			w[i] = self._left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

		# Initialize hash value for this chunk
		a = h0
		b = h1
		c = h2
		d = h3
		e = h4

		for i in range(80):
			if 0 <= i <= 19:
				# Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
				f = d ^ (b & (c ^ d))
				k = 0x5A827999
			elif 20 <= i <= 39:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif 40 <= i <= 59:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			elif 60 <= i <= 79:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			a, b, c, d, e = ((self._left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
							 a, self._left_rotate(b, 30), c, d)

		# Add this chunk's hash to result so far
		h0 = (h0 + a) & 0xffffffff
		h1 = (h1 + b) & 0xffffffff
		h2 = (h2 + c) & 0xffffffff
		h3 = (h3 + d) & 0xffffffff
		h4 = (h4 + e) & 0xffffffff
 
		return h0, h1, h2, h3, h4


	def update(self, arg):
		"""Update the current digest.

		This may be called repeatedly, even after calling digest or hexdigest.

		Arguments:
			arg: bytes, bytearray, or BytesIO object to read from.
		"""
		if isinstance(arg, (bytes, bytearray)):
			arg = io.BytesIO(arg)

		# Try to build a chunk out of the unprocessed data, if any
		chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

		# Read the rest of the data, 64 bytes at a time
		while len(chunk) == 64:
			self._h = self._process_chunk(chunk, *self._h)
			self._message_byte_length += 64
			chunk = arg.read(64)

		self._unprocessed = chunk
		return self

	def digest(self):
		"""Produce the final hash value (big-endian) as a bytes object"""
		return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

	def hexdigest(self):
		"""Produce the final hash value (big-endian) as a hex string"""
		return '%08x%08x%08x%08x%08x' % self._produce_digest()

	def _produce_digest(self):
		"""Return finalized digest variables for the data processed so far."""
		# Pre-processing:
		message = self._unprocessed
		message_byte_length = self._message_byte_length + len(message)

		# append the bit '1' to the message
		message += b'\x80'

		# append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
		# is congruent to 56 (mod 64)
		message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

		# append length of message (before pre-processing), in bits, as 64-bit big-endian integer
		message_bit_length = message_byte_length * 8
		message += struct.pack(b'>Q', message_bit_length)

		# Process the final chunk
		# At this point, the length of the message is either 64 or 128 bytes.
		h = self._process_chunk(message[:64], *self._h)

		if len(message) == 64:
			return h
		return self._process_chunk(message[64:], *h)

def pad(s, pad_len=16):
	s_len = len(s)
	resto = s_len % pad_len
	b_len = pad_len - resto
	pad = bytes([ b_len ]) * b_len
	return s + pad

def xor(x1, x2):
	assert len(x1) == len(x2)
	r = b''
	for i in range(len(x1)):
		r += bytes([ x1[i] ^ x2[i] ])
	return r

def encrypt_AES_ECB(plaintext, key):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	assert len(plaintext) % 16 == 0
	ct = cipher.encrypt(plaintext)
	return ct

def encrypt_AES_CBC(plaintext, key, iv):
	n = 16
	assert len(key) == n
	assert len(iv) == n
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

def decrypt_AES_ECB(data, key):
	assert len(key) == 128/8
	cipher = AES.new(key, AES.MODE_ECB)
	pt = cipher.decrypt(data)
	return pt

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

def decrypt_AES_CBC(ciphertext, key, iv):
	n = 16
	assert len(key) == n
	assert len(iv) == n
	ciphertext_len = len(ciphertext)
	assert ciphertext_len % n == 0

	blocks = [ciphertext[i:i+n] for i in range(0, ciphertext_len, n)]
	pt = b''
	previus_block = iv

	for block in blocks:
		d_block = decrypt_AES_ECB(block, key)
		pt_block = xor(d_block, previus_block)
		pt += pt_block
		previus_block = block
	return unpad(pt)

def randomString(stringLength):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

class Person():

	def genPK(self):
		self.a = random.randint(1, self.p - 1)
		self.A = pow(self.g, self.a, self.p)

	def getPK(self):
		return [self.g, self.p, self.A]

	def recvPK(self, B):
		self.B = B
		self.s = pow(self.B, self.a, self.p)

	def setCurve(self, g, p):
		self.g = g
		self.p = p

	def sendMessage(self, message):
		key = Sha1Hash().update(str(self.s).encode('utf-8')).digest()[:16]
		iv = rand_bytes(16)
		ct = encrypt_AES_CBC(message, key, iv)
		return base64.b64encode(iv + ct)

	def recvMessage(self, message):
		key = Sha1Hash().update(str(self.s).encode('utf-8')).digest()[:16]
		iv_ct = base64.b64decode(message)
		iv = iv_ct[:16]
		ct = iv_ct[16:]
		return decrypt_AES_CBC(ct, key, iv).decode('utf-8')



# Iterative Function to calculate  
# (x ^ y)%p in O(log y)  
def powmod(x, y, p):  
  
	res = 1; # Initialize result  
  
	x = x % p; # Update x if it is more  
			   # than or equal to p  
  
	while (y > 0):  
		  
		# If y is odd, multiply x with result  
		if (y & 1):  
			res = (res * x) % p;  
  
		# y must be even now  
		y = y >> 1; # y = y/2  
		x = (x * x) % p;  
	return res;  

# Function to calculate k for given a, b, m  
def discreteLogarithm(a, b, m):  
	n = int(math.sqrt(m) + 1);

	value = [0] * m;

	# Store all values of a^(n*i) of LHS  
	for i in range(n, 0, -1):  
		value[ pow (a, i * n, m) ] = i;  

	for j in range(n):
		  
		# Calculate (a ^ j) * b and check  
		# for collision  
		cur = (pow (a, j, m) * b) % m;

		# If collision occurs i.e., LHS = RHS  
		if (value[cur]):  
			ans = value[cur] * n - j;  
			  
			# Check whether ans lies below m or not  
			if (ans < m):
				return ans;

	return -1;  

def mitm():
	g = 2
	p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

	alice = Person()
	alice.setCurve(g, p)
	alice.genPK()
	g, p, A = alice.getPK()

	# Eve
	evilA = p

	bob   = Person()
	bob.setCurve(g, p)
	bob.genPK()
	B = bob.getPK()[2]
	bob.recvPK(evilA)

	# Eve
	evilB = p

	alice.recvPK(evilB)
	ct = alice.sendMessage( randomString(20).encode('utf-8') )

	m = bob.recvMessage(ct)
	print('msg recv:{}'.format(m))

	"""
	A = g ^ a mod p
	B = g ^ b mod p

	s = B ^ a mod p

	B = p

	s = p ^ a mod p = 0
	"""

	key = Sha1Hash().update(b'0').digest()[:16]
	iv_ct = base64.b64decode(ct)
	iv = iv_ct[:16]
	ct = iv_ct[16:]
	m = decrypt_AES_CBC(ct, key, iv).decode('utf-8')

	print('msg was :{}'.format(m))

if __name__ == '__main__':
	mitm()