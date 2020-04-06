#!/usr/bin/python3
# -*- coding: utf-8 -*-

import hashlib
import sys
sys.path.append("..")
from cryptolib import *

def random_string(stringLength):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

class Client():

	def __init__(self, I, P, N, g, k):
		self.I = I
		self.P = P
		self.N = N
		self.g = g
		self.k = k

	def genA(self):
		self.a = random.randint(1, self.N - 1)
		self.A = pow(self.g, self.a, self.N)
		return self.A

	def genK(self, salt, B):
		self.salt = salt
		self.B = B

		h = hashlib.sha256()
		h.update(str(self.A).encode('utf-8') + str(self.B).encode('utf-8'))
		uH = h.hexdigest()
		u = int(uH, 16)
		h = hashlib.sha256()
		h.update(self.salt + self.P)
		xH = h.hexdigest()
		x = int(xH, 16)
		aux = self.B - self.k * pow(self.g, x, self.N) # add modulo N
		S = pow(aux, self.a + u * x, self.N)
		h = hashlib.sha256()
		h.update(str(S).encode('utf-8'))
		self.K = h.hexdigest()
		return self.K

class Server():

	def __init__(self, N, g, k):
		self.users = {}
		self.N = N
		self.g = g
		self.k = k

	def addUser(self, I, P):
		self.users[I] = P

	def genB(self, I, A):
		self.A = A

		assert I in self.users
		P = self.users[I]
		self.salt = rand_bytes(16)
		h = hashlib.sha256()
		h.update(self.salt + P)
		xH = h.hexdigest()
		x = int(xH, 16)
		self.v = pow(self.g, x, self.N)

		self.b = random.randint(1, self.N - 1)
		self.B = (self.k * self.v) + pow(self.g, self.b, self.N)
		return [self.salt, self.B]

	def genK(self):
		h = hashlib.sha256()
		h.update(str(self.A).encode('utf-8') + str(self.B).encode('utf-8'))
		uH = h.hexdigest()
		u = int(uH, 16)
		aux = self.A * pow(self.v, u, self.N) # add modulo N
		S = pow(aux, self.b, self.N)
		h = hashlib.sha256()
		h.update(str(S).encode('utf-8'))
		self.K = h.hexdigest()
		return self.K

def SRP(C, S):
	A = C.genA()

	salt, B = S.genB(C.I, A)

	Kc = C.genK(salt, B)

	Ks = S.genK()

	if Kc == Ks:
		print('shared key:{}'.format(Kc))
	else:
		print('Failed!')

def main():
	I = b'user@mail.com'
	P = random_string(20).encode('utf-8')
	N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
	g = 2
	k = 3

	c = Client(I, P, N, g, k)
	s = Server(N, g, k)
	s.addUser(I, P)

	SRP(c, s)

if __name__ == '__main__':
	main()
