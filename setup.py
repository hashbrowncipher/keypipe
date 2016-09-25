from setuptools import setup, Extension
from setuptools import find_packages

libaepipe = Extension('aepipe/_libaepipe',
    sources = ['c/libaepipe.c'],
    libraries = ['crypto'],
)

setup(
    name='aepipe',
    version='0.0.1',
    author='Josh Snyder',
    author_email='josh@code406.com',
    packages = ['aepipe'],
    ext_modules = [libaepipe],
    cffi_modules=['cffi_builders/lib.py:ffi'],
    zip_safe=False,
)
