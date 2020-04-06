#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
sys.path.append("..")
from cryptolib import *

class MD4(object):
    def __init__(self, data=b""):
        self.remainder = data
        self.count = 0
        self.h = [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
                ]

    def leftrotate(self, i, n):
        return ((i << n) & 0xffffffff) | (i >> (32 - n))

    def F(self, x,y,z):
        return (x & y) | (~x & z)

    def G(self, x,y,z):
        return (x & y) | (x & z) | (y & z)

    def H(self, x,y,z):
        return x ^ y ^ z

    def _add_chunk(self, chunk):
        self.count += 1
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in range(16):
            i = (16-r)%4
            k = r
            h[i] = self.leftrotate( (h[i] + self.F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
        # Round 2
        s = (3,5,9,13)
        for r in range(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            h[i] = self.leftrotate( (h[i] + self.G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in range(16):
            i = (16-r)%4 
            h[i] = self.leftrotate( (h[i] + self.H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def update(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = b""
        for chunk in range(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def digest(self):
        l = len(self.remainder) + 64 * self.count
        self.update( b"\x80" + b"\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8) )
        out = struct.pack("<4I", *self.h)
        self.__init__()
        return out

    def set_registers(self, h0, h1, h2, h3):
        self.h = [
                int.from_bytes(h0, "little"),
                int.from_bytes(h1, "little"),
                int.from_bytes(h2, "little"),
                int.from_bytes(h3, "little")
        ]

def HMAC_MD4(message, key):
    md = MD4()
    md.update(key + message)
    d = md.digest().hex()
    return d

def check_mac(message, mac, key):
    return HMAC_MD4(message, key) == mac

def get_padding(message_byte_length):
    remainder = message_byte_length % 64
    count = message_byte_length // 64
    l = remainder + 64 * count
    pad = b"\x80" + b"\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8)
    return pad

def length_extension_md4(oldmac, oldmsg, keylen, extension):

    pad = get_padding( keylen + len(oldmsg) )

    n = 4
    h0, h1, h2, h3 = [oldmac[i:i+n] for i in range(0, 16, n)]

    md = MD4()
    md.set_registers(h0, h1, h2, h3)
    md.remainder = b''
    md.count = ((keylen + len(oldmsg) + len(pad)) // 64)
    md.update(extension)
    new_mac = md.digest().hex()

    new_msg = oldmsg + pad + extension

    return [new_mac, new_msg]

def main():

    keylen = random.randint(16, 64)
    key =  rand_bytes(keylen)

    msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = HMAC_MD4(msg, key)
    mac = bytes.fromhex(mac)

    msg_extension = b";admin=true"

    print('message is:')
    print(msg)
    print('mac is')
    print(mac.hex())
    print('')

    new_mac, new_msg = length_extension_md4(mac, msg, keylen, msg_extension)

    if check_mac(new_msg, new_mac, key):
        print('new msg is:')
        print(new_msg)
        print('new mac is:')
        print(new_mac)
    else:
        print('Failed!')


if __name__=="__main__":
    main()
