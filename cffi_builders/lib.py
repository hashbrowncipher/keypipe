from os.path import abspath
from os.path import join
from os.path import dirname

from cffi import FFI

ffi = FFI()

def get_c_filename(*args):
    mydir = dirname(abspath(__file__))
    return join(dirname(mydir), 'c', *args)

def get_c_contents(*args):
    return open(get_c_filename(*args), 'r').read()

ffi.cdef(get_c_contents('libaepipe.h'))
ffi.set_source(
    "keypipe._libaepipe",
    '#include "libaepipe.h"',
    libraries=['crypto'],
    sources=['c/libaepipe.c'],
    include_dirs=['c']
)

if __name__ == "__main__":
    ffi.compile()
