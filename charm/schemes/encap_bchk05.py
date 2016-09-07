from __future__ import absolute_import, print_function, unicode_literals
from charm.compatibility import compat_str, compat_bytes
from charm.core.math.integer import randomBits
import hashlib

debug = False
class EncapBCHK():
    """
    >>> encap = EncapBCHK()
    >>> hout = encap.setup()
    >>> (r, com, dec) = encap.S(hout)
    >>> rout = encap.R(hout, com, dec)
    >>> r == rout
    True
    """
    def __init__(self):
        global H
        H = hashlib.sha1()

    def setup(self):
        pub = hashlib.sha256()
        return pub

    def S(self, pub):
        x = randomBits(448)
        x = compat_str(x).zfill(135)

        r = hashlib.sha256(x.encode('utf-8')).digest()

        com = hashlib.sha1(x.encode('utf-8')).digest()[:128]

        dec = x

        return (r, com, dec)

    def R(self, pub, com, dec):
        x = hashlib.sha1(compat_str(dec).encode('utf-8')).digest()[:128]
        
        if(x == com):
            m = hashlib.sha256(compat_str(dec).encode('utf-8')).digest()
            return m
        else:
            return b'FALSE'
