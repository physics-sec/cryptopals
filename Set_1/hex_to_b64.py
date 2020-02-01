#!/usr/bin/python2
# -*- coding: utf-8 -*-

import base64

string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

s = string.decode('hex')

print type(s)

b64 = base64.b64encode(s)

print(b64)