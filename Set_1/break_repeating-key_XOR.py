


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


