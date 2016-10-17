import os


def subparser_kwargs():
    return dict(help='Reads keys from a file')


def customize_parser(parser):
    parser.add_argument('filename', help='File to read the key from')
    parser.set_defaults(func=seal)


def get_keypair(args):
    key = os.urandom(32)
    os.umask(umask | 0077)
    with open(args.file, 'wb') as f:
        f.write(key)
    return key, ''


def decrypt_blob(args):
    with open(args.file, 'rb') as f:
        return f.read(32)
