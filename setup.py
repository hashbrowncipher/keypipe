import sys

from setuptools import setup, Extension
from setuptools import find_packages

install_requires = [
  "cffi>=1.0.0",
  "contexter>=0.1.3",
]

if sys.version_info.major < 3:
    install_requires.append("futures>=3.0.5")

setup(
    name='keypipe',
    version='0.0.1',
    author='Josh Snyder',
    author_email='josh@code406.com',
    packages = ['keypipe'],
    setup_requires=["cffi>=1.0.0"],
    install_requires=install_requires,
    cffi_modules=['cffi_builders/lib.py:ffi'],
    entry_points=dict(
        console_scripts=[
            'keyseal=keypipe.cli:seal',
            'keyunseal=keypipe.cli:unseal',
        ],
    ),
)
