import sys

if sys.version_info >= (3, 0):
    compat_str = str
    compat_bytes = bytes
else:
    compat_str = unicode
    compat_bytes = str



# Python 2.7.12 (default, Jul  1 2016, 15:12:24)
# [GCC 5.4.0 20160609] on linux2
# Type "help", "copyright", "credits" or "license" for more information.
# >>> type(u'0-9')
# <type 'unicode'>
# >>> type('0-9')
# <type 'str'> -> becomes 'unicode' with __future__.unicode_literals
# >>> type(b'0-9')
# <type 'str'>
# >>>


# >>> sys.version_info >= (3,0)
# True
# >>> type(u'0-9')
# <class 'str'>
# >>> type('0-9')
# <class 'str'>
# >>> type(b'0-9')
# <class 'bytes'>
