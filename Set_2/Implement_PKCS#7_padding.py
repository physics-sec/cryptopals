
def pad(s, length):
	b_len = length - len(s)
	assert b_len > 0
	return s + chr(b_len) * b_len

print pad("YELLOW SUBMARINE", 20)
