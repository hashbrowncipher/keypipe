from setuptools import setup, Extension
from setuptools import find_packages

libaeadpipe = Extension('aeadpipe/_libaeadpipe',
    sources = ['c/libaeadpipe.c'],
    libraries = ['crypto'],
)

setup(
    name='aeadpipe',
    version='0.0.1',
    author='Josh Snyder',
    author_email='josh@code406.com',
    packages = ['aeadpipe'],
    ext_modules = [libaeadpipe],
    cffi_modules=['cffi_builders/lib.py:ffi'],
    zip_safe=False,
)
