#!/usr/bin/python3
# -*- coding: utf-8 -*-

import time
import random

class MT19937:

    def __init__(self):
        # The coefficients for MT19937 are:
        (self.w, self.n, self.m, self.r) = (32, 624, 397, 31)
        self.a = 0x9908B0DF
        (self.u, self.d) = (11, 0xFFFFFFFF)
        (self.s, self.b) = (7, 0x9D2C5680)
        (self.t, self.c) = (15, 0xEFC60000)
        self.l = 18
        
        # The value for f for MT19937 is 1812433253
        self.f = 1812433253
        
        # Create a length n array to store the state of the generator
        self.MT = []
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1 # That is, the binary number of r 1's
        self.upper_mask = (~self.lower_mask) & 0xFFFFFFFF # lowest w bits of (not lower_mask)
        
    # Initialize the generator from a seed
    def seed_mt(self, seed):
        self.index = self.n
        self.MT = [seed]
        for i in range(1, (self.n - 1) + 1): # loop over each element
            nextval = (self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i) & 0xFFFFFFFF # lowest w bits
            self.MT.append(nextval)
    
    # Extract a tempered value based on MT[index]
    # calling twist() every n numbers
    def extract_number(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator was never seeded")
                # Alternatively, seed with constant value; 5489 is used in reference C code[48]
            self.twist()
    
        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
    
        self.index = self.index + 1
        return y & 0xFFFFFFFF # lowest w bits of (y)
    
    # Generate the next n values from the series x_i 
    def twist(self):
        for i in range(0, (self.n - 1) + 1):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0: # lowest bit of x is 1
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0


def getrand(rng):
    timestamp = int(time.time())
    timestamp += random.randint(40, 1000)

    rng.seed_mt(timestamp)

    return [rng.extract_number(), timestamp]

def main():

    rng  = MT19937()
    
    r, seed = getrand(rng)
    timestamp  = int(time.time())
    timestamp += 20000

    print('actual seed:{:d}'.format(seed))
    print('   start at:{:d}'.format(timestamp))

    num = 0
    while num != r:
        timestamp -= 1
        rng.seed_mt(timestamp)
        num = rng.extract_number()

    print('\nFound seed: {:d}'.format(timestamp))


if __name__ == '__main__':
    main()
