#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import hmac
import string
import random
import hashlib

def randomString(stringLength):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

class Server():

	def __init__(self, N, g):
		self.users = {}
		self.N = N
		self.g = g

	def addUser(self, I, P):
		self.users[I] = P

	def genB(self, I, A):
		self.A = A
		assert I in self.users
		P = self.users[I]
		self.salt = os.urandom(16)
		h = hashlib.sha256()
		h.update(self.salt + P)
		xH = h.hexdigest()
		x = int(xH, 16)
		self.v = pow(self.g, x, self.N)
		self.b = random.randint(1, self.N - 1)
		self.B = pow(self.g, self.b, self.N)
		uB = os.urandom(126 // 8).hex()
		self.u = int(uB, 16)
		return [self.salt, self.B, self.u]

	def genK(self):
		aux = self.A * pow(self.v, self.u, self.N) # add modulo N
		S = pow(aux, self.b, self.N)
		h = hashlib.sha256()
		h.update(str(S).encode('utf-8'))
		self.K = h.hexdigest()
		return self.K

	def check_mac(self, mac):
		real_mac = hmac.new(self.K.encode('utf-8'), self.salt, hashlib.sha256).hexdigest()
		return hmac.compare_digest(mac, real_mac)

class Client():

	def __init__(self, I, P, N, g):
		self.I = I
		self.P = P
		self.N = N
		self.g = g

	def genA(self):
		self.a = random.randint(1, self.N - 1)
		self.A = pow(self.g, self.a, self.N)
		return self.A

	def genK(self, salt, B, u):
		self.salt = salt
		self.B = B
		h = hashlib.sha256()
		h.update(self.salt + self.P)
		xH = h.hexdigest()
		x = int(xH, 16)
		S = pow(self.B, self.a + u * x, self.N)
		h = hashlib.sha256()
		h.update(str(S).encode('utf-8'))
		self.K = h.hexdigest()
		return self.K

	def gen_mac(self):
		return hmac.new(self.K.encode('utf-8'), self.salt, hashlib.sha256).hexdigest()


"""
I know:
- HMAC-SHA256(K, salt)
- A
- g and N

I control:
- salt
- B
- u

I don't know:
- K
- a
- x

This challenge obviously isn't about breaking HMAC
but I can use HMAC-SHA256(K, salt) as a way to test weather
I have the right K (and therefore the right password)

To derive the right K, I first need S
To know S, I need to know 'a' and 'x'

To know 'a', I have to to solve the discrete logaritm for
Log g(A) mod N, which is very very hard (because I don't control N, and is very large)

Once I know 'a', I can generate multiple 'x's by trying several passwords
x = SHA-256(salt | password)

for each 'x', I would calculate S (using 'a')
S = B ** ('a' + u * 'x')

and then calculate K from S
K = SHA256(S)

at last, I would test K calculating
HMAC-SHA256(K, salt) == known MAC
to test if I got the right password

"""

def solve_discrete_loraritm(g, A, N):
	raise Exception('unimplemented.')

def SRP_mitm(C, N, g):
	A = C.genA()

	salt = b'\x00' * 16
	B = random.randint(1, N - 1)
	u = 1

	C.genK(salt, B, u)

	mac = C.gen_mac()

	#a = solve_discrete_loraritm(g, A, N)
	a = C.a

	while True:
		password = randomString(5).encode('utf-8')
		h = hashlib.sha256()
		h.update(salt + password)
		xH = h.hexdigest()
		x = int(xH, 16)
		S = pow(B, a + u * x, N)
		h = hashlib.sha256()
		h.update(str(S).encode('utf-8'))
		K = h.hexdigest()
		mac_try = hmac.new(K.encode('utf-8'), salt, hashlib.sha256).hexdigest()
		if mac_try == mac:
			print('password:{}'.format(password.decode('utf-8')))
			return

def SRP_normal(C, S):
	A = C.genA()

	salt, B, u = S.genB(C.I, A)

	Kc = C.genK(salt, B, u)

	Ks = S.genK()

	mac = C.gen_mac()
	crack_mac(mac)

	valid = S.check_mac(mac)

	if valid:
		print('shared key:{}'.format(Kc))
	else:
		print('Failed!')
	return Kc

def main():
	I = b'user@mail.com'
	P = randomString(5).encode('utf-8')
	N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
	g = 2

	c = Client(I, P, N, g)
	s = Server(N, g)
	s.addUser(I, P)

	SRP_mitm(c, N, g)
	#SRP_normal(c, s)

	

if __name__ == '__main__':
	main()
