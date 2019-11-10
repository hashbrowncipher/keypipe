import pytest

from keypipe._aepipe import _unseal_unchecked, AEError, unseal

from test.helpers import *


def expect_exception(key, in_, out):
    assert do_aepipe(key, in_, _unseal_unchecked) == out
    with pytest.raises(AEError):
        do_aepipe(key, in_, unseal)


def test_empty():
    in_ = b"\x01" + b"\x00" * 12 + uh("763c62df413000674199240567321ec1")
    assert do_aepipe(docs_key, in_, unseal) == b""


def test_corrupted_empty():
    key = uh("bdccdb944d9f1f560d66a5615bd4c9e93ae84184eda521643d7f6c88e5cf6908")
    in_ = b"\x01" + b"\x00" * 12 + uh("763c62df413000674199240567321ec0")
    expect_exception(docs_key, in_, b"")


def test_gcm13():
    in_ = b"\x01" + b"\x00" * 12 + uh("530f8afbc74536b9a963b4f1c4cb738b")
    assert do_aepipe(b"\x00" * 32, in_, unseal) == b""


def test_gcm14():
    in_ = (
        b"\x01"
        + b"\x00" * 8
        + b"\x00\x00\x00\x10"
        + uh("d0d1c8a799996bf0265b98b5d48ab919" "cea7403d4d606b6e074ec5d3baf39d18")
        + uh("0" * 8 + "8486364fc8409762f6e6232b65376b97")
    )
    assert do_aepipe(b"\x00" * 32, in_, unseal) == b"\x00" * 16


multiblock_input = uh(
    b"0100000000000000000000001042383e"
    b"688cdc28310032bf683884b4ca57e265"
    b"9c232bc95768cbc1e884be1b77000000"
    b"10fe0600c28a45c3f91a31f44227c094"
    b"ae81343222464c156cef14dc03fac5be"
    b"ca000000002cdadcc7aa85815378fb58"
    b"1fe8f49795"
)


def test_multiblock():
    assert do_aepipe(docs_key, multiblock_input, unseal) == b"\x00" * 32


def test_multiblock_truncated():
    expect_exception(docs_key, multiblock_input[:-21], b"\x00" * 16)


def test_multiblock_verytruncated():
    expect_exception(docs_key, multiblock_input[:-40], b"")


def test_multiblock_corrupted():
    in_ = bytearray(multiblock_input)
    in_[-21] ^= 0xFF
    in_ = bytes(in_)
    expect_exception(docs_key, in_, b"\x00" * 16)
