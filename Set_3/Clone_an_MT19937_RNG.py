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

def unstep1(y):

    c = 0
    aux = y ^ ((y >> 11) & 0xFFFFFFFF)
    aux = aux & 0xFFFFF800
    c |= aux

    aux = y ^ ((aux & 0x3FF800) >> 11)
    aux = aux & 0x7FF
    c |= aux

    return c

def unstep2(y):

    c = 0
    aux = y & 0x7F
    c |= aux

    aux = y ^ ((aux << 7) & 0x9D2C5680)
    aux = aux & 0x3F80
    c |= aux

    aux = y ^ ((aux << 7) & 0x9D2C5680)
    aux = aux & 0x1FC000
    c |= aux

    aux = y ^ ((aux << 7) & 0x9D2C5680)
    aux = aux & 0xFE00000
    c |= aux

    aux = y ^ ((aux << 7) & 0x9D2C5680)
    aux = aux & 0x7F0000000
    c |= aux

    return c

def unstep3(y):

    c = 0
    aux = y & 0x7FFF
    c |= aux

    aux = y ^ ((aux << 15) & 0xEFC60000)
    aux = aux & 0x3FFF8000
    c |= aux

    aux = y ^ ((aux << 15) & 0xEFC60000)
    aux = aux & 0x1FFFC0000000
    c |= aux

    aux = y ^ ((aux << 15) & 0xEFC60000)
    aux = aux & 0xFFFE00000000000
    c |= aux

    return c

def unstep4(y):
    c = y ^ (y >> 18)
    return c

def untemper(y):
    y = unstep4(y)
    y = unstep3(y)
    y = unstep2(y)
    y = unstep1(y)
    return y

def main():
    rng = MT19937()
    rng.seed_mt(random.randint(0,1000))

    state = []
    for b in range(624):
        state.append( untemper( rng.extract_number() ) )

    rng_copy       = MT19937()
    rng_copy.MT    = state
    rng_copy.n     = 624
    rng_copy.index = 624

    print('rng_copy.extract_number:{:d}'.format(rng_copy.extract_number()))
    print('rng.extract_number     :{:d}'.format(rng.extract_number()))


if __name__ == '__main__':
    main()
