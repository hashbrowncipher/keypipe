from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from io import BytesIO
import binascii
import os

from contexter import Contexter

from keypipe._aepipe import closing_fd

uh = binascii.unhexlify
docs_key = uh('bdccdb944d9f1f560d66a5615bd4c9e93ae84184eda521643d7f6c88e5cf6908')

def drain_into(pipe, to):
    while True:
        d = os.read(pipe, 8192)
        if len(d) == 0:
            break
        to.write(d)

@contextmanager
def aepipe_ctx(key, buf, op):
    with Contexter() as ctx:
        executor = ctx << ThreadPoolExecutor(max_workers=2)
        
        (input_r, input_w) = os.pipe()
        (output_r, output_w) = os.pipe()

        ctx << closing_fd(output_r)
        output_closer = ctx << closing_fd(output_w)
        ctx << closing_fd(input_r)
        input_closer = ctx << closing_fd(input_w)

        aepipe_f = executor.submit(op, key, input_r, output_w)
        output_f = executor.submit(drain_into, output_r, buf)

        yield input_w

        input_closer.close()
        aepipe_f.result()

        output_closer.close()
        output_f.result()

def do_aepipe(key, in_, op):
    buf = BytesIO()
    with aepipe_ctx(key, buf, op) as p:
        os.write(p, in_)
    return buf.getvalue()


