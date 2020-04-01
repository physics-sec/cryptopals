#!/usr/bin/python3
# -*- coding: utf-8 -*-

import gmpy2
import hashlib
import subprocess

class RSA():

	def __init__(self):
		self.prime_size = 1024

	def egcd(self, a, b):
		if a == 0:
			return (b, 0, 1)
		else:
			g, y, x = self.egcd(b % a, a)
			return (g, x - (b // a) * y, y)

	def invmod(self, a, m):
		g, x, y = self.egcd(a, m)
		if g != 1:
			raise Exception('modular inverse does not exist')
		else:
			return x % m

	def gen_prime(self):
		process = subprocess.Popen(['openssl', 'prime', '-generate', '-bits', str(self.prime_size), '-hex'], stdout=subprocess.PIPE)
		prime = process.communicate()[0][:-1]
		prime = int(prime.decode('utf-8'), 16	)
		return prime

	def gen_keypair(self):
		p = self.gen_prime()
		q = self.gen_prime()
		if p == q:
			return self.gen_keypair()
		self.n = p * q
		et = (p - 1) * (q - 1)
		self.e = 3
		self.d = self.invmod(self.e, et)

	def get_public_key(self):
		return [self.e, self.n]

	def get_private_key(self):
		return [self.d, self.n]

	def int_to_bytes(self, integer, size=None):
		hex_string = "%x" % integer
		if len(hex_string) % 2 == 1:
			hex_string = '0' + hex_string
		if size and len(hex_string) // 2 < size:
			nullbytes = '00' * (size - len(hex_string) // 2)
			hex_string = nullbytes  + hex_string
		return bytes.fromhex(hex_string)

	def bytes_to_int(self, byte_arr):
		return int.from_bytes(byte_arr, 'big')

	def verify(self, signature, message, e=None, n=None):
		if e is None and n is None:
			e = self.e
			n = self.n
		k = len(self.int_to_bytes(self.n))

		signature = self.bytes_to_int(signature)
		message_obtained = pow(signature, e, n)
		message_obtained = self.int_to_bytes(message_obtained, k)

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
		k = len(self.int_to_bytes(self.n))

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

		block = self.bytes_to_int(block)
		if block > self.n:
			raise Exception('block is longer than n')
		signature = pow(block, self.d, self.n)
		signature = self.int_to_bytes(signature)
		return signature

"""
0x00 0x01 0xff..ff 0x00 IDh H(m)
IDh -> identifier string of the hash function
hash of the message

768 bits de padding, 256 bits de hash

https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/
"""

def main():
	rsa = RSA()
	rsa.gen_keypair()
	e, n = rsa.get_public_key()

	message = b'hi mom'
	real_signature = rsa.sign(message)
	print('real signature:{}\n'.format(real_signature.hex()))

	h = hashlib.sha256()
	h.update(message)
	digest = h.digest()

	ASNSHA256 = b"\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
	for null_pad in range(1000):
		block  = b'\x00\x01\xff\x00' + ASNSHA256 + digest

		block += b'\x00' * null_pad

		block_int = rsa.bytes_to_int(block)

		cube_root, rest = gmpy2.iroot_rem(block_int, 3)
		cube_root  = int(cube_root)
		cube_root += 1

		evil_signature = rsa.int_to_bytes(cube_root)

		valid = rsa.verify(evil_signature, message)

		if valid:
			print('spoofed signature:{}'.format(evil_signature.hex()))
			return
		else:
			pass

if __name__ == '__main__':
	main()
