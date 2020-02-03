
import base64
import decimal
import string

fd = open('6.txt', 'r')
data = fd.read()
fd.close()
ct = base64.b64decode( data.replace('\n', '') )

def hamming_distance(s1, s2):
	assert len(s1) == len(s2)

	diff_bits = 0
	for i in xrange(len(s1)):
		b1 = ord(s1[i])
		b2 = ord(s2[i])
		x = b1 ^ b2
		for i in xrange(8):
			if x & (2 ** i):
				diff_bits -=- 1

	return diff_bits

def getkeysize():
	# doesn't work
	distancias = []
	for KEYSIZE in xrange(2, 40 + 1):
		chunk1 = ct[:KEYSIZE]
		chunk2 = ct[KEYSIZE:KEYSIZE*2]
		distance =  decimal.Decimal(hamming_distance(chunk1, chunk2)) / KEYSIZE
		chunk3 = ct[KEYSIZE*2:KEYSIZE*3]
		chunk4 = ct[KEYSIZE*4:KEYSIZE*5]
		distance2 =  decimal.Decimal(hamming_distance(chunk3, chunk4)) / KEYSIZE
		distance = (distance + distance2) / decimal.Decimal(2)
		distancias.append( [KEYSIZE, distance] )
		#print KEYSIZE, distance

	distancias = sorted(distancias, key=lambda elem: elem[1])
	keysize = distancias[0][0]
	return keysize

def get_key(keysize):
	chunks = [ ct[i:i+keysize] for i in range(0, len(ct), keysize) ]
	# print chunks

	trasposed = []

	for i in xrange(keysize):
		t_block = ''.join( [ block[i] for block in chunks[:-1] ] )
		trasposed.append(t_block)
	for i, c in enumerate(chunks[-1]):
		trasposed[i] += c
	# print trasposed

	key = ''
	for chunk in trasposed:
		pts = []
		for k in xrange(0xff + 1):
			r = ''
			for b in chunk:
				r += chr( ord(b) ^ k )

			valid = True
			puntos = 0
			for c in r:
				if c not in string.printable:
					valid = False
					break
				elif c == ' ':
					puntos += 2
				elif c in string.ascii_letters:
					puntos += 1
			if valid:
				pts.append([k, puntos, r])
		if len(pts) == 0:
			return None

		choise = sorted(pts, key=lambda elem: elem[1])[-1][0]
		key += chr(choise)
	if key == '':
		return None
	return key

def main():

	keysize = getkeysize()

	for keysize in xrange(2, 40 + 1):
		key = get_key(keysize)
		if key:
			print 'keysize: ' + str(keysize)
			print 'key: ' + key
			pt = ''
			for i, c in enumerate(ct):
				pt += chr( ord(c) ^ ord(key[i % keysize]) )
			print 'plaintext:\n' + pt

if __name__ == '__main__':
	main()
