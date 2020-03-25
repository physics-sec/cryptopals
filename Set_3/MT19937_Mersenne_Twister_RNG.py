#!/usr/bin/python3
# -*- coding: utf-8 -*-

# The coefficients for MT19937 are:
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18

# The value for f for MT19937 is 1812433253
f = 1812433253

# Create a length n array to store the state of the generator
MT = []
index = n + 1
lower_mask = (1 << r) - 1 # That is, the binary number of r 1's
upper_mask = (~lower_mask) & 0xFFFFFFFF # lowest w bits of (not lower_mask)

# Initialize the generator from a seed
def seed_mt(seed):
    global index, MT
    index = n
    MT = [seed]
    for i in range(1, (n - 1) + 1): # loop over each element
        nextval = (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i) & 0xFFFFFFFF # lowest w bits
        MT.append(nextval)

# Extract a tempered value based on MT[index]
# calling twist() every n numbers
def extract_number():
    global index
    if index >= n:
        if index > n:
            raise Exception("Generator was never seeded")
            # Alternatively, seed with constant value; 5489 is used in reference C code[48]
        twist()

    y = MT[index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index = index + 1
    return y & 0xFFFFFFFF # lowest w bits of (y)

# Generate the next n values from the series x_i 
def twist():
    global index
    for i in range(0, (n - 1) + 1):
        x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0: # lowest bit of x is 1
            xA = xA ^ a
        MT[i] = MT[(i + m) % n] ^ xA
    index = 0

seed_mt(1234)

print(extract_number())
print(extract_number())
print(extract_number())
