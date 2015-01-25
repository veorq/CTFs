#!/usr/bin/env python

# Copyright (c) 2014 Nagravision SA, all rights reserved

import os
import sys
import hashlib
from Crypto.Cipher import AES

ZEROBLOCK = '\x00'*16

def encrypt(key, iv, plaintext):
    assert len(key) == 16, 'key isnt 16-byte'
    assert len(iv) == 16, 'iv isnt 16-byte'
    assert len(plaintext) % 16 == 0, 'plaintext length isnt multiple of 16'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)


def xor(xs, ys):
    return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))


class PRNG(object):

    def __init__(self):
        self.state_bytes = 64
        self.key = ZEROBLOCK
        self.iv = ZEROBLOCK
        # get low-entropy string from the environment
        entropy = ''.join(os.listdir('/proc'))
        # hash to make a higher-entropy string
        seed = int(hashlib.sha256(entropy).hexdigest(), 16)
        # ensure distinct processes have distinct seeds
        pid = os.getpid()
        new_seed = self.__diversify(pid) * seed
        # hash again to get a 32-byte string
        final_seed = hashlib.sha256(str(new_seed)).digest()
        # initialize state
        self.state = final_seed + '\x00'*(self.state_bytes - len(final_seed))
        # fill state with pseudorandom bytes
        # + proof-of-work, against bruteforce
        for i in range(10000):
            self.__update()

    def __print_state(self):
        print self.state.encode('hex')

    def __diversify(self, x):
        return pow(3, x, 65537) & 0xffff

    def __update(self):
        mask = encrypt(self.key, self.iv, self.state)
        self.state = xor(mask, self.state)

    def get_bytes(self, nbbytes):
        randbytes = self.state[-nbbytes:]
        self.__update()
        return randbytes


def main():
    prng = PRNG()
    plaintext = open(sys.argv[1]).read()
    key = prng.get_bytes(16)
    iv = ZEROBLOCK
    ciphertext = encrypt(key, iv, plaintext)
    print ciphertext.encode('hex')

if __name__ == '__main__':
    main()
