from contextlib import contextmanager

import hashlib
from hmac import new as _hmac
import importlib
import os

from . import _aepipe
from ._aepipe import AEError
from .serialization import serialize
from .serialization import deserialize

AEError = _aepipe.AEError

providers = dict(
    kms='keypipe.managers.kms',
    vault='keypipe.managers.vault',
    keyfile='keypipe.managers.keyfile',
)

class InvalidKeyError(RuntimeError):
    pass

def hmac(key, data, func):
    return _hmac(key, data, func).digest()

def _hkdf_generator(ikm, salt, info):
    # Using SHA-512 and truncating its output is explicitly endorsed by
    # https://eprint.iacr.org/2010/264.pdf , pg. 27
    # Appendix D, #4
    prk = hmac(salt, ikm, func=hashlib.sha512)[:32]
    t = b""
    for i in range(0, 255):
        t = hmac(prk, t + info + bytes([1+i]), hashlib.sha256)
        yield t

def get_provider_module(module_name):
    return importlib.import_module(module_name)

def get_provider_by_name(name):
    module_name = providers[name]
    return get_provider_module(module_name)

def derive_key(ikm, salt, context):
    generator = _hkdf_generator(ikm, salt, context)
    key = next(generator)

    # Hugo Krawczyk. "Cryptographic Extraction and Key Derivation: The HKDF
    # Scheme" https://eprint.iacr.org/2010/264.pdf p.21
    # explicitly endorses disclosing other output from the KDF:
    #   "Second, if the leakage of an output from the KDF, in this case the
    #   public IV, can compromise other (secret) keys output by the KDF,
    #   then the scheme is fully broken; indeed, it is an essential requirement
    #   that the leakage of one key produced by the KDF should not compromise
    #   other such keys"
    checksum = next(generator)

    return checksum, key

def seal(provider_name, provider_args, context, in_fileno, out_fileno):
    module = get_provider_by_name(provider_name)
    (plaintext, blob) = module.get_keypair(**provider_args)

    salt = os.urandom(64)
    checksum, key = derive_key(plaintext, salt, context)

    # The checksum serves only to identify whether the correct key has been
    # derived. Most of the header could be garbage, but if we manage to produce
    # a correct key, the checksum will match.
    header = serialize(salt, checksum, { provider_name: blob })
    out_fileno.write(header)
    out_fileno.flush()
    _aepipe.seal(key, in_fileno, out_fileno)

@contextmanager
def closing_fd(fd):
    try:
        yield fd
    finally:
        os.close(fd)

class UnconfiguredProviderException(Exception):
    pass

def unseal(provider_args, context, infile, outfile):
    salt, checksum, providers = deserialize(infile)
    for name, blob in providers:
        if name not in provider_args:
            continue

        args = provider_args[name]
        manager = get_provider_by_name(name)
        plaintext = manager.read_blob(blob, **args)

    derived_checksum, key = derive_key(plaintext, salt, context)
    if derived_checksum != checksum:
        raise InvalidKeyError

    _aepipe.unseal(key, infile, outfile)
