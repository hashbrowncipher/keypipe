from contextlib import contextmanager

import importlib
import os
import struct

from contexter import Contexter

from . import _aepipe

providers = dict(
    kms='keypipe.managers.kms',
    vault='keypipe.managers.vault',
    keyfile='keypipe.managers.keyfile',
)

MAGIC = b'AE|'
VERSION = 1

class InsufficientDataError(RuntimeError):
    pass

class UnrecognizedMagicError(RuntimeError):
    pass

class UnrecognizedVersionError(RuntimeError):
    pass

def get_header(name, blob):
    encoded_name = name.encode('ascii')
    total_len = 1 + len(name) + len(blob)
    pack_format = '!3sBHB{}s'.format(len(encoded_name))
    packed = struct.pack(pack_format,
                         MAGIC,
                         VERSION,
                         total_len,
                         len(encoded_name),
                         encoded_name,
                )
    return packed + blob

def read_header(infile):
    initial_input = infile.read(7)
    if len(initial_input) != 7:
        raise InsufficientDataError

    d = struct.unpack('!3sBHB', initial_input)
    got_magic, got_version, total_len, name_len = d
    if got_magic != MAGIC:
        raise UnrecognizedMagicError

    if got_version != VERSION:
        raise UnrecognizedVersionError

    name_and_blob = infile.read(total_len - 1)
    name = name_and_blob[:name_len].decode('ascii')
    blob = name_and_blob[name_len:]
    return name, blob

def get_provider_module(module_name):
    return importlib.import_module(module_name)

def get_provider_by_name(name):
    module_name = providers[name]
    return get_provider_module(module_name)

def seal(provider_name, provider_args, in_fileno, out_fileno):
    module = get_provider_by_name(provider_name)
    (key, blob) = module.get_keypair(**provider_args)
    header = get_header(provider_name, blob)
    os.write(out_fileno, header)
    _aepipe.seal(key, in_fileno, out_fileno)

@contextmanager
def closing_fd(fd):
    try:
        yield fd
    finally:
        os.close(fd)

class UnconfiguredProviderException(Exception):
    pass

def unseal(provider_args, infile, outfile):
    provider, blob = read_header(infile)
    try:
        args = provider_args[provider]
    except KeyError:
        raise UnconfiguredProviderException()
    manager = get_provider_by_name(provider)
    key = manager.read_blob(blob, **args)
    _aepipe.unseal(key, infile, outfile)
