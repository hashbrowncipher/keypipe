from __future__ import absolute_import

from six import reraise
from subprocess import PIPE
from threading import Thread
import functools
import sys

from plumbum.commands import BaseCommand


class PipelineToThread(BaseCommand):
    __slots__ = ['_cmd', '_func']
    def __init__(self, cmd, func):
        self._cmd = cmd
        self._func = func

    def __repr__(self):
        return "%s(%r, %r)" % (type(self).__name__, self._cmd, self._func)

    @property
    def machine(self):
        return self._cmd.machine

    def popen(self, args=(), **kwargs):
        kwargs['stdout'] = PIPE
        p = self._cmd.popen(**kwargs)
        p._thread_exception = None

        original_stdout = p.stdout
        @functools.wraps(self._func)
        def func(*args, **kwargs):
            try:
                self._func(*args, **kwargs)
            except:
                e = sys.exc_info()
                p._thread_exception = e
            finally:
                original_stdout.close()

        # prevent the main thread from reading from stdout
        p.stdout = None

        t = Thread(target=func, args=(original_stdout,))
        t.start()
        
        original_wait = p.wait
        def wait(*args, **kwargs):
            t.join()
            code = original_wait(*args, **kwargs)
            if p._thread_exception:
                reraise(*p._thread_exception)
            return code
        p.wait = wait
        return p

BaseCommand.__div__ = lambda s, o: PipelineToThread(s, o)
