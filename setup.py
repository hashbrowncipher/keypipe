from setuptools import setup, Extension
from setuptools import find_packages

setup(
    name='aepipe',
    version='0.0.1',
    author='Josh Snyder',
    author_email='josh@code406.com',
    packages = ['aepipe'],
    cffi_modules=['cffi_builders/lib.py:ffi'],
)
