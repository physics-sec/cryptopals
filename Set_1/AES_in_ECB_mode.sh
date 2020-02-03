#!/bin/bash
openssl enc -aes-128-ecb -d -a -in 7.txt -K $(echo "YELLOW SUBMARINE" | xxd -p) -iv 1
