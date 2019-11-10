import os
from io import BytesIO
from test.helpers import aepipe_ctx
from test.helpers import as_int
from test.helpers import do_aepipe
from test.helpers import docs_key
from test.helpers import sha256
from test.helpers import uh

from keypipe._aepipe import seal


def test_empty():
    expected = b"\x01" + b"\x00" * 12 + uh("763c62df413000674199240567321ec1")
    assert do_aepipe(docs_key, b"", seal) == expected


def test_multiblock():
    buf = BytesIO()
    with aepipe_ctx(docs_key, buf, seal) as p:
        for i in range(129):
            os.write(p, b"\x00" * 8192)

    # instead of following line there should be some check, propably?
    output_value = buf.getvalue()

    # version
    assert output_value[0] == 1

    # iv
    assert output_value[1:9] == b"\x00" * 8

    assert as_int(output_value[9:13]) == 1_048_576
    start = 13
    start += 16
    start += 1_048_576

    assert as_int(output_value[start : start + 4]) == 8192

    start += 4
    start += 16
    start += 8192

    assert as_int(output_value[start : start + 4]) == 0

    start += 4
    start += 16

    assert len(output_value) == start
    assert (
        sha256(output_value)
        == "b76e03b3f3e5f59a5f15a13bd87c1767358bb9787546415a3b0a78ea450d6c69"
    )


def test_gcm13():
    expected = b"\x01" + b"\x00" * 12 + uh("530f8afbc74536b9a963b4f1c4cb738b")
    assert do_aepipe(b"\x00" * 32, b"", seal) == expected


def test_gcm14():
    expected = (
        b"\x01"
        + b"\x00" * 8
        + b"\x00\x00\x00\x10"
        + uh("d0d1c8a799996bf0265b98b5d48ab919" + "cea7403d4d606b6e074ec5d3baf39d18")
        + uh("0" * 8 + "8486364fc8409762f6e6232b65376b97")
    )
    assert do_aepipe(b"\x00" * 32, b"\x00" * 16, seal) == expected
