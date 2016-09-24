from setuptools import setup, Extension

setup(
    name='aeadpipe',
    version='0.0.1',
    cffi_modules=['cffi_builders/lib.py:ffi']
)
