from __future__ import absolute_import

from os import O_CLOEXEC
from os import pipe2
import io
import os

from six import reraise
from subprocess import PIPE
from threading import Thread
import functools
import sys

from plumbum.commands import BaseCommand
from plumbum.machines.base import PopenAddons

def get_thread(func, args=None, kwargs=None):
    return Thread(target=func, args=args, kwargs=kwargs)

class PopenedThread(Thread, PopenAddons):
    def wait(self):
        self.join()
        e = self.exception[0]
        if e is not None:
            reraise(*e)
        self.returncode = 0
        return self.returncode

class ThreadCommand(BaseCommand):
    __slots__ = ['_func']

    @staticmethod
    def _wrapper(func, stdin, stdout, exception):
        try:
            func(stdin, stdout)
        except:
            e = sys.exc_info()
            exception[0] = e
        finally:
            # We want writers to get SIGPIPE
            stdin.close()
            # and readers to get EOF
            stdout.close()

    def __init__(self, func):
        self._func = func

    def popen(self, args=(), **kwargs):
        bufsize = kwargs.get('bufsize', -1)

        stdin = kwargs.get('stdin', sys.stdin)
        stdin.close = close
        exposed_stdin = None
        if stdin == PIPE:
            (r, w) = pipe2(O_CLOEXEC)

            stdin = io.open(r, 'rb', bufsize)
            exposed_stdin = io.open(w, 'wb', bufsize)

        stdout = kwargs.get('stdout', sys.stdout)
        exposed_stdout = None
        if stdout == PIPE:
            (r, w) = pipe2(O_CLOEXEC)

            stdout = w
            exposed_stdout = io.open(r, 'rb', bufsize)
        else:
            stdout = os.dup(stdout)
       
        stdout = io.open(stdout, 'wb', bufsize)

        exception = [None]
        t = PopenedThread(target=self._wrapper, args=(self._func, stdin, stdout, exception))
        t.stdin = exposed_stdin
        t.stdout = exposed_stdout
        t.stderr = None
        t.exception = exception
        t.start()

        return t
 

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
        kwargs = kwargs.copy()
        thread_stdout = kwargs.get('stdout', sys.stdout)
        kwargs['stdout'] = PIPE

        p = self._cmd.popen(bufsize=0, **kwargs)
        thread_stdin = p.stdout

        # Wrap self._func in order to catch its exceptions (these we will
        # re-raise in the main thread. We'll also close the subprocess's
        # stdout when the thread exits.
        p._thread_exception = None
        @functools.wraps(self._func)
        def func(*args, **kwargs):
            try:
                self._func(*args, **kwargs)
            except:
                e = sys.exc_info()
                p._thread_exception = e
            finally:
                # Let our subprocess know that nobody is reading its output
                # anymore. Let any downstream processes know that nobody is 
                # producing input for it anymore.
                thread_stdin.close()
                thread_stdout.close()

        if thread_stdout == PIPE:
            (p2cread, p2cwrite) = pipe2(O_CLOEXEC)

            # expose the thread's stdout on the Popen object
            p.stdout = io.open(p2cread, 'rb')
            thread_stdout = p2cwrite
        else:
            thread_stdout = os.dup(thread_stdout.fileno())

            # prevent caller from reading from the subprocess's stdout
            # that's not its job.
            p.stdout = None

        thread_stdout = io.open(thread_stdout, 'wb')

        t = get_thread(func, args=(thread_stdin, thread_stdout))

        original_wait = p.wait
        def wait(*args, **kwargs):
            code = original_wait(*args, **kwargs)
            t.join()
            if p._thread_exception:
                reraise(*p._thread_exception)
            return code
        p.wait = wait

        t.start()
        return p

BaseCommand.__truediv__ = lambda s, o: PipelineToThread(s, o)
