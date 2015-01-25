#!/usr/bin/env python

import os
import sys
import hashlib
from Crypto.Cipher import DES

"""
trick: python's mutable default arguments, cf.
http://stackoverflow.com/questions/101268/hidden-features-of-python#113198

what happens: 
* the first xor modifies the default output list to PID^salt_init; 

* this value gets prepended to the result of the subsequent xor between
  ent1 and ent2.

* then an 8-byte key is generated from the 32-byte state

* these 8 bytes depend only on the first 8 bytes of the state, which
  consist of the PID (first 7 bytes) followed by a random byte

* actual entropy of the key is thus only 23 bits: 15 bits (max pid is
  32768) + 8 bits, which can be bruteforced

"""


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


class PRNG2(object):

    def __init__(self, apid, abyte):
        self.key = '\x00'*8
        self.iv = '\x00'*8
        salt_init = '\x8a\x37\xb1\x0f\xaa\x91\x7e\x01'

        pid = '%07d' % apid
        salt = xor(salt_init, pid, 7, [])

        ent3 = salt + abyte + os.urandom(30)

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

def solve(ciphertext):
    iv = '\x00' * 8
    bytez = [ ('%02x' % x).decode('hex') for x in range(256)] 
    
    # bruteforce PID
    # to take a shortcut, use (say) range(32769)[1300:]:
    for pid in xrange(32769):
        print 'searching PID %d' % pid 
        for abyte in bytez:
            prng = PRNG2(pid, abyte)
            key = prng.get_bytes(8)
            plaintext = decrypt(key, iv, ciphertext)
            if plaintext[:8] == 'the flag':
                print 'key: ', key.encode('hex')
                print 'plaintext: ', plaintext
                return



if __name__ == '__main__':

    c = 'd962c7fc000d35ed46b08a11c6b18cf16331cebc37e23090'
    ciphertext = c.decode('hex')
    solve(ciphertext)

"""
output:

...
searching PID 1336
searching PID 1337
key:  3781baf9e9d10b84
plaintext:  the flag is IMMUTABILITY
"""
