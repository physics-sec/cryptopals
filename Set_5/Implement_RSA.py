#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

def main():
	rsa = RSA()
	rsa.gen_keypair()
	ct = rsa.encrypt(b'test string')
	pt = rsa.decrypt(ct).decode('utf-8')
	print(pt)

if __name__ == '__main__':
	main()
