

fd = open('8.txt', 'r')
lines = fd.read().split()
fd.close()

results = []
for line in lines:
	matches = 0
	chunks = [ line[i:i+32] for i in range(0, len(line), 32) ]
	for chunk1 in chunks:
		for chunk2 in chunks:
			if chunk1 == chunk2:
				matches += 1
	results.append( [matches, line] )

line = sorted(results, key=lambda elem: elem[0])[-1][1]
print line
