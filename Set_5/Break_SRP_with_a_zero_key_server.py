#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import random
import hashlib
from flask import Flask, render_template, request
app = Flask(__name__)

class Server():

	def __init__(self, N, g, k):
		self.users = {}
		self.N = N
		self.g = g
		self.k = k

	def addUser(self, I, P):
		self.users[I] = P.encode('utf-8')

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

@app.route('/srp', methods=['POST'])
def SRP():
	data = request.json
	A = data["A"]
	I = data["I"]

	try:
		salt, B = S.genB(I, A)
	except AssertionError:
		return '{"error": "user not found"}', 404

	Ks = S.genK()

	resp = '{{"salt": "{}", "B": {:d}}}'.format(salt.hex(), B)

	return resp, 200

@app.route('/check', methods=['POST'])
def check():
	data = request.json
	K = data["K"]

	if S.K == K:
		return 'Access granted', 200
	else:
		return 'Access denied', 403

if __name__ == '__main__':
	N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
	g = 2
	k = 3
	S = Server(N, g, k)
	I = 'user@mail.com'
	P = 'supersecretpassword'
	S.addUser(I, P)
	app.run(host="127.0.0.1", port=8000)
