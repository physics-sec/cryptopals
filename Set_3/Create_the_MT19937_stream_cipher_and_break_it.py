#!/usr/bin/python3
# -*- coding: utf-8 -*-

import time
import random
import string
import sys
sys.path.append("..")
from cryptolib import *

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

def MT19937Cipher(key, msg):
    assert key <= 0xffff
    rng = MT19937()
    rng.seed_mt(key)
    ct = b''
    for b in msg:
        x = rng.extract_number() ^ b
        x &= 0xff
        ct += bytes( [x] )
    return ct

def get_ct(pt):
    prefix = rand_bytes( random.randint(0, 20) )
    pt = prefix + pt
    key = random.randint(0, 0xffff)
    print('secret key:{:d}'.format(key))
    ct = MT19937Cipher(key, pt)
    return ct

def randomString(stringLength):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def recover_sk(pt, ct):

    unknown = ct[:-len(pt)]
    unknown_len = len(unknown)

    for key in range(0xffff + 1):
        rng = MT19937()
        rng.seed_mt(key)
        for x in range(len(ct)):
            rnum  = rng.extract_number()
            rnum &= 0xff
            if x == unknown_len:
                for i, b in enumerate(ct[unknown_len:]):
                    if rnum ^ b != pt[i]:
                        break
                    rnum  = rng.extract_number()
                    rnum &= 0xff
                else:
                    print('found key:{:d}'.format(key))
                    return

def password_reset_token():
    if random.randint(0, 1) == 1:
        print('used urandom for token')
        return rand_bytes(16).hex()
    else:
        print('used MT19937 for token')
        rng = MT19937()
        currtime = int(time.time())
        currtime -= 2000 # simulate old tokens time
        print('key:{:d}'.format(currtime))
        rng.seed_mt(currtime)
        token = b''
        for x in range(16):
            num = rng.extract_number()
            num &= 0xff
            token += bytes( [num] )
        return token.hex()

def check_token(token):
    token = bytes.fromhex(token)
    currtime = int(time.time())
    for secs in range(86400): # seconds in a day
        key = currtime - secs
        rng = MT19937()
        rng.seed_mt(key)
        for pos in range(len(token)):
            b = rng.extract_number()
            b &= 0xff
            if b != token[pos]:
                break
        else:
            print('recovered key:{:d}'.format(key))
            return True
    return False

def attack1():
    pt = randomString( random.randint(10, 30) ).encode('utf-8')
    ct = get_ct(pt)
    recover_sk(pt, ct)

def attack2():
    token = password_reset_token()
    if check_token(token):
        print('the token was generated via MT19937')
    else:
        print('the token was NOT generated via MT19937')

if __name__ == '__main__':
    pass
    #attack1()
    #attack2()
