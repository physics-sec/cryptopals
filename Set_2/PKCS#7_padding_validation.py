
def validate_padding(s):
	if len(s) % 16 != 0:
		raise Exception('Bad Padding!')
	pad_len = s[-1]
	if pad_len > 16 or pad_len < 1:
		raise Exception('Bad Padding!')
	for i in range(1, pad_len + 1):
		if s[-i] != pad_len:
			raise Exception('Bad Padding!')
	return s[:-pad_len]

validate_padding(b'ICE ICE BABY\x04\x04\x04\x04')
validate_padding(b'ICE ICE BABY\x05\x05\x05\x05')
validate_padding(b'ICE ICE BABY\x01\x02\x03\x04')
