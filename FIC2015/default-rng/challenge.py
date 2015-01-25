#!/usr/bin/env python

import os
import sys
import hashlib
from Crypto.Cipher import DES


def encrypt(key, iv, plaintext):
    assert len(key) == 8 
    assert len(iv) == 8 
    assert (len(plaintext) % 8) == 0
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)


def decrypt(key, iv, ciphertext):
    assert len(key) == 8 
    assert len(iv) == 8 
    assert (len(ciphertext) % 8) == 0
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def xor(in1, in2, n, out=[]):
    for i in range(n):
        out.append( chr(ord(in1[i]) ^ ord(in2[i])) )
    return ''.join(out)


class PRNG(object):

    def __init__(self):
        self.key = '\x00'*8
        self.iv = '\x00'*8
        salt_init = '\x8a\x37\xb1\x0f\xaa\x91\x7e\x01'

        pid = '%07d' % os.getpid()
        salt = xor(salt_init, pid, 7)

        ent1 = hashlib.sha256(salt).digest()
        ent2 = os.urandom(32)
        ent3 = xor(ent1, ent2, 32)

        # initialize 32B state 
        self.state = ''
        for i in range(32):
            self.state += ent3[i]
        self.__update()

    def __update(self):
        mask = encrypt(self.key, self.iv, self.state)
        self.state = xor(mask, self.state, 32, [])

    def get_bytes(self, nbbytes):
        randbytes = self.state[:nbbytes]
        self.__update()
        return randbytes


def main():
    prng = PRNG()
    key = prng.get_bytes(8)
    iv = '\x00' * 8
    plaintext = open('plaintext').read().rstrip('\n')
    ciphertext = encrypt(key, iv, plaintext)
    print ciphertext.encode('hex')


if __name__ == '__main__':
    main()
