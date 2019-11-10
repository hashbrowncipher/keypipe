import fcntl
import os
from contextlib import closing
from contextlib import contextmanager
from errno import EBADF
from errno import EPERM
from threading import Lock

from contexter import Contexter

from ._libaepipe import ffi
from ._libaepipe import lib

if not hasattr(fcntl, "F_SETPIPE_SZ"):
    import platform

    if platform.system() == "Linux":
        fcntl.F_SETPIPE_SZ = 1031


class AEError(RuntimeError):
    def __init__(self, code):
        self.msg = ffi.string(lib.aepipe_errorstrings[code]).decode("utf-8")

    def __str__(self):
        return self.msg


class CloseableFd(int):
    _closed = False

    def close(self):
        if not self._closed:
            self._closed = True
            os.close(self)


def closing_fd(fd):
    return closing(CloseableFd(fd))


@contextmanager
def open_fd(filename, mode):
    fd = os.open(filename, mode, 0o666)
    with closing_fd(fd):
        yield fd


def _prep_file(ctx, f, mode):
    if not isinstance(f, int):
        try:
            f = f.fileno()
        except AttributeError:
            f = ctx << open_fd(f, mode)

    exceptions_to_catch = (IOError,)
    try:
        exceptions_to_catch += (PermissionError,)
    except NameError:
        pass

    try:
        fcntl.fcntl(f, fcntl.F_SETPIPE_SZ, 1024 * 1024)
    except exceptions_to_catch as e:
        if e.errno not in (EPERM, EBADF):
            raise

    return f


def _check(ret):
    if ret != 0:
        raise AEError(ret)


def _seal(key, context, in_file, out_file):
    casted_aepipe_context = ffi.cast("struct aepipe_context *", ffi.addressof(context))
    with Contexter() as contexter:
        in_file = _prep_file(contexter, in_file, os.O_RDONLY)
        out_file = _prep_file(
            contexter, out_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        )

        _check(lib.aepipe_seal(key, casted_aepipe_context, in_file, out_file))


class Seal(object):
    __slots__ = ("_context", "_lock", "_key")

    def __init__(self, key):
        """Instantiates a Seal
        key: 32 random bytes. Using the same key multitple times destroys the
        security guarantees of AES-GCM.
        """
        if len(key) != lib.KEYSIZE:
            raise RuntimeError(
                "The provided key is length {}, expected {}".format(
                    len(key), lib.KEYSIZE
                )
            )
        self._key = key

        # aepipe has its own very basic locking here
        # it will return an error when used inappropriately
        # this will do the waiting for you
        self._lock = Lock()
        self._context = ffi.new("char[]", lib.aepipe_context_size())

    def seal(self, in_file, out_file):
        with self._lock:
            _seal(self._key, self._context, in_file, out_file)


def _unseal_unchecked(key, in_file, out_file):
    with Contexter() as contexter:
        in_file = _prep_file(contexter, in_file, os.O_RDONLY)
        out_file = _prep_file(
            contexter, out_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        )
        return lib.aepipe_unseal(key, in_file, out_file)


def unseal(*args):
    _check(_unseal_unchecked(*args))


def seal(key, in_file, out_file):
    Seal(key).seal(in_file, out_file)
