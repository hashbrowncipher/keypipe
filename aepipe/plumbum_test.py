from __future__ import absolute_import

from gevent import monkey
monkey.patch_all()

from time import sleep
from plumbum.cmd import dd
from plumbum import FG

import aepipe.plumbum 

def printer(inpipe):
    i = 0
    while i < 20:
        l = inpipe.read(20)
        if not l:
            break
        print(len(l))
        sleep(0.01)
        i += 1

ddprint = dd['if=/dev/zero', 'bs=20', 'count=20'] / printer
from IPython import embed; embed()
