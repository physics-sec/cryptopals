#!/usr/bin/python3
# -*- coding: utf-8 -*-

import time
import string
import random
import requests
from decimal import *

def randomString(stringLength):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

def main():

	ratio = 0.7
	rounds_per_byte = 2

	file = randomString(7)

	url_base = 'http://127.0.0.1:9000/test?file={}&signature='.format(file)

	signature = b''

	for b_nro in range(20):
		candidats = list(range(255 + 1))

		score = {}
		while len(signature) == b_nro:

			byte_delay = {}
			average = 0
			for x in range(rounds_per_byte):
				for b in candidats:
					sig = signature
					sig += bytes( [b] )
					sig += b'\x00' * (20 - len(sig))
					sig  = sig.hex()
					url  = url_base + sig
					start = time.time_ns()
					r = requests.post(url)
					finish = time.time_ns()
					real_mac = r.text
					delay = Decimal(finish) - Decimal(start)
					if b not in byte_delay:
						byte_delay[b] = 0	
					byte_delay[b] += delay
					average += delay / Decimal(len(candidats))

			# sort
			byte_delay = {k: v for k, v in sorted(byte_delay.items(), key=lambda item: -item[1])}
			a = ''
			for k in byte_delay:
				a += bytes([k]).hex() + ' '
			print(a)

			old_candidats = len(candidats)

			for i, b in enumerate(byte_delay):
				if b not in score:
					score[b] = 0
				score[b] += byte_delay[b] / average

			score = {k: v for k, v in sorted(score.items(), key=lambda item: -item[1])}

			new_score = score.copy()
			candidats = []
			for i, b in enumerate(score):
				i += 1
				if i <= (Decimal(ratio) * Decimal(old_candidats)):
					candidats.append(b)
				else:
					del new_score[b]

			score = new_score.copy()

			if len(candidats) == 1:
				signature += bytes( [candidats[0]] )
				print('signature:{}'.format(signature.hex() + '__' * (20 - len(signature))))
				print('real sig :{}\n'.format(real_mac))
				if signature[b_nro] != bytes.fromhex(real_mac)[b_nro]:
					print('Fail!')
					return

	r = requests.post(url_base + signature.hex())
	if r.status_code == 200:
		print('\n\nsignature: {}'.format(signature.hex()))
		print(r.text)
	else:
		print('Fail!')

if __name__ == '__main__':
	try:
		main()
	except requests.exceptions.ConnectionError:
		print('ConnectionRefusedError')
