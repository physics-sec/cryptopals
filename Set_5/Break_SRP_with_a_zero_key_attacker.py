#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import random
import hashlib
import requests

def main():
	url_base = 'http://127.0.0.1:8000'

	N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
	I = 'user@mail.com'
	A = N * random.randint(0, 2)

	data = '{{"A": {:d}, "I": "{}"}}'.format(A, I)
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
		}

	r = requests.post(url_base + '/srp', data=data, headers=headers)

	resp = json.loads(r.text, strict=True)

	if "error" in resp:
		print(resp["error"])
		return

	S = b'0'
	h = hashlib.sha256()
	h.update(S)
	K = h.hexdigest()

	data = '{{"K": "{}"}}'.format(K)
	r = requests.post(url_base + '/check', data=data, headers=headers)

	if r.status_code == 200:
		print('Key: {}'.format(K))
		print(r.text)
	else:
		print('Fail!')

if __name__ == '__main__':
	main()
