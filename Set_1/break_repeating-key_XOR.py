
import base64
import decimal
import string
from math import gcd

fd = open('6.txt', 'r')
data = fd.read()
fd.close()
ct = base64.b64decode( data.replace('\n', '') )

def hamming_distance(s1, s2):
	assert len(s1) == len(s2)

	diff_bits = 0
	for i in range(len(s1)):
		b1 = ord(s1[i])
		b2 = ord(s2[i])
		x = b1 ^ b2
		for i in range(8):
			if x & (2 ** i):
				diff_bits -=- 1

	return diff_bits

def find_single_byte_xor(ct):
	frec = {}

	for b in ct:
		if b not in frec:
			frec[b] = 1
		else:
			frec[b] += 1

	frec = sorted(frec, key=lambda elem: -frec[elem])

	resp = []
	for b in frec:
		# space is likely the most common char in plain text
		key = ord(' ') ^ b
		r = b''
		valid = True
		for i in range(len(ct)):
			c = bytes([ ct[i] ^ key ])
			if c not in bytes(string.printable, 'ascii'):
				valid = False
				break
			r += c
		if valid is False:
			continue
		#r = str(r,'ascii')
		resp.append(key)
	return resp

def getkeysize(ct):
	offsets = []
	maxlen = len(ct)

	i = 0
	while i < maxlen:
		j = i + 1
		while j < maxlen:
			length = 0
			while j + length < maxlen:
				if ct[i + length] == ct[j + length]:
					length += 1
				else:
					break
			if length >= 3:
				offsets.append( j - i )
				break
			j += 1
		i += length + 1

	divisors = {}
	for i in range(len(offsets)-1):
		divisor = gcd(offsets[i], offsets[i+1])
		if divisor == 1:
			continue
		if divisor not in divisors:
			divisors[divisor] = 1
		else:
			divisors[divisor] += 1
	divisors = sorted(divisors, key=lambda elem: -divisors[elem])

	return divisors

def get_key(keysize, ct):
	chunks = [ ct[i:i+keysize] for i in range(0, len(ct), keysize) ]

	trasposed = []
	for i in range(keysize):
		[ block[i] for block in chunks[:-1] ]
		t_block = b''.join( [ bytes([ block[i] ]) for block in chunks[:-1] ] )
		trasposed.append(t_block)
	for i, c in enumerate(chunks[-1]):
		trasposed[i] += bytes([ c ])

	key = ''
	for chunk in trasposed:

		keys = find_single_byte_xor(chunk)
		if len(keys) > 0:
			key += chr(keys[0])
		else:
			return None

		if key == '':
			return None

	return key

def xor_with_key(ct, key):
	index = 0
	pt = ''
	for c in ct:
		pt += chr( c ^ ord(key[index % len(key)]) )
		index -=- 1
	return pt

def main():

	keysizes = getkeysize(ct)
	keysize = keysizes[0]

	key = get_key(keysize, ct)

	print('keysize: ' + str(keysize))
	print('key: ' + key)
	pt = xor_with_key(ct, key)
	print('plaintext:\n' + pt)

if __name__ == '__main__':
	main()
