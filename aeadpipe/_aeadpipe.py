from os.path import dirname
from os.path import join
from threading import Lock
import os

from cffi import FFI

from ._lib import ffi
lib = ffi.dlopen(join(dirname(__file__), 'libaeadpipe.so'))

class AEADError(RuntimeError):
    def __init__(self, code):
        self.msg = ffi.string(lib.aeadpipe_errorstrings[code])

    def __str__(self):
        return self.msg

def convert_file(f, mode):
    try:
        f.fileno()
    except AttributeError:
        f = open(f, mode)

    return f

def check(ret):
    if ret != lib.OK:
        raise AEADError(ret)

def _seal(key, context, in_file, out_file):
    casted_context = ffi.cast('struct gcm_context *', ffi.addressof(context))
    check(lib.aeadpipe_encrypt(key, casted_context,
            convert_file(in_file, 'rb'),
            convert_file(out_file, 'wb')))

class Seal(object):
    __slots__ = ('_context', '_lock', '_key')

    def __init__(self, key):
        """Instantiates a Seal
        key: 32 random bytes. Using the same key multitple times destroys the
        security guarantees of AES-GCM.
        """
        self._key = key
        self._lock = Lock() # definitely not re-entrant
        self._context = ffi.new('char[]', lib.gcm_context_size())

    def seal(self, in_file, out_file):
        with self._lock:
            _seal(self._key, self._context, in_file, out_file)


def unseal(key, in_file, out_file):
    in_file = convert_file(in_file, 'rb')
    out_file = convert_file(out_file, 'wb')
    check(lib.aeadpipe_decrypt(key, in_file, out_file))

def seal(key, in_file, out_file):
    Seal(key).seal(in_file, out_file)
