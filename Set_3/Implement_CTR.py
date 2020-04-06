#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

def main():
	msg = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	msg = base64.b64decode(msg)

	key = b'YELLOW SUBMARINE'

	nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'

	pt = CTR(msg, key, nonce)

	print(pt)

if __name__ == '__main__':
	main()
