#!/usr/bin/python3
# -*- coding: utf-8 -*-

import io
import sys
sys.path.append("..")
from cryptolib import *

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
	ct = alice.sendMessage( random_string(20).encode('utf-8') )

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
