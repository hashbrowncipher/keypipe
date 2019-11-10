from __future__ import print_function

import argparse
import functools
import importlib
import os
import struct
import sys
import traceback

import keypipe


class InvalidMagicError(Exception):
    pass


class UnrecognizedVersionError(Exception):
    def __init__(self, version):
        self.version = version


# there is seriously nothing in stdlib that composes two functions?
def wrap(t):
    def decorator(fn):
        "Function decorator to transform a generator into a list"

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return t(fn(*args, **kwargs))

        return wrapper

    return decorator


@wrap(list)
def get_providers():
    for name, module_name in providers:
        module = None
        exception = None
        tagline = None
        try:
            module = importlib.import_module(module_name)
            if hasattr(module, "get_tagline"):
                tagline = module.get_tagline()
        except Exception as e:
            exception = traceback.format_exc()

        yield name, module, exception, tagline


def get_header(name, blob):
    magic = "AE|"
    version = 1
    total_length = 1 + len(name) + len(blob)
    pack_format = "!3sBHB{}s".format(len(name))
    packed = struct.pack(pack_format, magic, version, total_length, len(name), name)
    return packed + blob


def indent(s):
    return "  " + s.replace("\n", "\n  ").rstrip()


def write_blob():
    parser = argparse.ArgumentParser(
        description="Piped authenticated encryption with key management"
    )
    plugin_parsers = parser.add_subparsers(
        title="key_provider", help="provider to use for key management"
    )
    providers = get_providers()
    for (name, module, exception) in providers:
        if module:
            got_args = True

            get_parser_args = getattr(module, "get_parser_args", None)
            if get_parser_args is not None:
                try:
                    args, kwargs = get_parser_args()
                except Exception as e:
                    got_args = False
            else:
                r = (tuple(), dict())

            if got_args:
                try:
                    p = plugin_parsers.add_parser(name, *args, **kwargs)
                    module.customize_parser(p)
                    p.set_defaults(plugin_name=name)
                except:
                    pass

    args = parser.parse_args()
    key = os.urandom(32)
    blob = args.func(key, args)
    os.write(sys.stdout.fileno(), get_header(args.plugin_name, blob))
    return key


def read_header(fileno):
    pre_header = os.read(fileno, 6)
    magic, version, next_len = struct.unpack("!3sBH", pre_header)

    if magic != "AE|":
        raise InvalidMagicError()

    if version != 1:
        raise UnrecognizedVersionError(version)

    header = os.read(fileno, next_len)
    plugin_len = ord(header[0])

    plugin = header[1 : plugin_len + 1]
    blob = header[plugin_len + 1 :]
    return (plugin, blob)


def read_key(argv):
    STDIN_FILENO = sys.stdin.fileno()
    provider, blob = read_header(STDIN_FILENO)
    module, exception = get_provider(provider)

    if not module:
        print(
            "Trying to import the {} provider failed with this exception".format(
                provider
            )
        )
        print(indent(exception), file=sys.stderr)
        return None

    return module.decrypt_blob(blob, argv)


def seal():
    key = write_blob()
    keypipe.seal(key, 0, 1)


def get_split_providers():
    providers = get_providers()

    available_providers = [
        (name, module, tagline)
        for name, module, exception, tagline in providers
        if exception is None
    ]

    broken_providers = [
        (name, exception)
        for name, module, exception, tagline in providers
        if exception is not None
    ]

    return available_providers, broken_providers


def do_unseal_help(available, broken):
    if len(available) > 0:
        print("Available key providers:", file=sys.stderr)
        for name, _, tagline in available:
            print(name, file=sys.stderr, end="")
            if tagline is not None:
                print(":\t{}".format(tagline), file=sys.stderr)
            else:
                print(file=sys.stderr)
    else:
        print("No key providers loaded succesfully", file=sys.stderr)

    if len(broken) > 0:
        print(file=sys.stderr)
        print("The following providers failed to load:")
        for name, exception in broken:
            print("{}:".format(name), file=sys.stderr)
            print(indent(exception), file=sys.stderr)


def get_provider(name):
    return dict(
        (name, (module, exception)) for (name, module, exception) in get_providers()
    ).get(name)


def do_plugin_help(name):
    provider = get_provider(name)
    if provider is None:
        print("Unknown unseal key provider: {}".format(name))
        return 1

    (module, exception) = provider
    if exception is not None:
        print(
            "The {} key provider failed to load, with the following exception:".format(
                name
            ),
            file=sys.stderr,
        )
        print(indent(exception), file=sys.stderr)
        return 1

    get_unseal_help = getattr(module, "get_unseal_help", None)
    if get_unseal_help is None:
        print(
            "The {} unseal key provider requires no configuration".format(name),
            file=sys.stderr,
        )
    else:
        print("Help for the {} unseal key provider:".format(name), file=sys.stderr)
        print()
        print(module.get_unseal_help())
    return 0


def do_unseal():
    key = read_key(sys.argv[1:])
    if key is None:
        return 1

    keypipe.unseal(key, 0, 1)


def do_unseal_tty():
    (available, broken) = get_split_providers()
    parser = argparse.ArgumentParser(
        description="Piped authenticated decryption with key management", add_help=False
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Forces unseal even when stdin is a tty",
    )
    parser.add_argument(
        "--help",
        "-h",
        action="store",
        metavar="PROVIDER",
        help="Display help for a specific key provider",
        choices=[name for name, _, _ in available],
    )

    (known_args, known_unknowns) = parser.parse_known_args()

    if len(known_unknowns) == 2 and known_unknowns[0].lower() == "help":
        return do_plugin_help(known_unknowns[1])

    if known_args.force:
        return do_unseal()

    parser.print_help()
    print(file=sys.stderr)
    return do_unseal_help(available, broken)


def unseal():
    if sys.stdin.isatty():
        return do_unseal_tty()
    else:
        return do_unseal()


if __name__ == "__main__":
    sys.exit(unseal())
