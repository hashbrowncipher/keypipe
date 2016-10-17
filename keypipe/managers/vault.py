import argparse
import base64
import json
import os
import textwrap
from textwrap import TextWrapper
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

try:
    import requests
except ImportError:
    raise ImportError("this key provider requires 'requests' to operate")

known_envvars = (
    ('VAULT_ADDR', 'The address of the Vault server expressed as a URL and port, for example: http://127.0.0.1:8200'),
    ('VAULT_TOKEN', 'The Vault authentication token. If not specified, the token located in $HOME/.vault-token will be used if it exists.'),
    ('VAULT_CACERT', 'Path to a PEM-encoded CA cert file used to verify the Vault server SSL certificate'),
    ('VAULT_CAPATH', 'Path to a directory of PEM-encoded CA cert files to verify the Vault server SSL certificate. If VAULT_CACERT is specified, its value will take precedence.'),
)


def get_parser_args():
    kwargs = dict(
        help="Retrieves keys from Hashicorp Vault's transit backend"
    )
    return tuple(), kwargs


def customize_parser(p):
    p.add_argument('--addr', help='overrides VAULT_ADDR',
                   default=os.getenv('VAULT_ADDR', None))
    p.add_argument('--cacert', help='overrides VAULT_CACERT',
                   default=os.getenv('VAULT_CACERT', None))
    p.add_argument('--capath', help='overrides VAULT_CAPATH',
                   default=os.getenv('VAULT_CAPATH', None))
    p.add_argument('name', help='Transit key name')
    p.add_argument('mountpoint', help='Transit mountpoint',
                   default='transit', nargs='?')
    p.set_defaults(func=encrypt_key)


def _get_token_filename():
    token_filename = os.environ.get('VAULT_TOKEN', None)
    if token_filename is not None:
        return token_filename

    token_filename = '.vault-token'
    home = os.environ.get('HOME', None)
    if home is not None:
        token_filename = os.path.join(home, token_filename)

    return token_filename


def _get_token():
    return open(_get_token_filename(), 'rb').read()


def _get_unseal_parser():
    wrap = TextWrapper(subsequent_indent=' ' * 18)

    def format_envvar(e):
        return wrap.fill('\t'.join(e))

    envvars_string = '\n  ' + '\n  '.join(map(format_envvar, known_envvars))

    parser = argparse.ArgumentParser(
        usage=argparse.SUPPRESS,
        description=textwrap.fill("Unseals using keys from Hashicorp Vault's transit backend.\nThis key provider understands the following standard Vault client environment variables:") +
        envvars_string + '\n\n' +
        textwrap.fill(
            'The transit mountpoint and key name are stored within the sealed output file. It is usually not necessary to specify when unsealing.'),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    parser.add_argument('--addr', help='overrides VAULT_ADDR',
                        default=os.getenv('VAULT_ADDR', None))
    parser.add_argument('--cacert', help='overrides VAULT_CACERT',
                        default=os.getenv('VAULT_CACERT', None))
    parser.add_argument('--capath', help='overrides VAULT_CAPATH',
                        default=os.getenv('VAULT_CAPATH', None))
    parser.add_argument(
        '--mountpoint', '-m', help='overrides the Transit mountpoint specified in the sealed file')
    parser.add_argument('--name', '-n', help='Transit key name')
    return parser


def get_unseal_help():
    return _get_unseal_parser().format_help()


def _vault_request(path, data, args):
    verify = True
    if args.capath is not None:
        verify = args.capath
    if args.cacert is not None:
        verify = args.cacert

    headers = {
        'X-Vault-Token': _get_token(),
    }
    url = urljoin(args.addr, path)
    response = requests.put(url,
                            json=data,
                            headers=headers,
                            verify=verify,
                            )
    response.raise_for_status()
    return response.json()


def encrypt_key(key, args):
    params = {
        'plaintext': base64.b64encode(key),
    }
    path = '/v1/{}/encrypt/{}'.format(args.mountpoint, args.name)
    ciphertext = _vault_request(path, params, args)['data']['ciphertext']
    return json.dumps(dict(
        ciphertext=ciphertext,
        mountpoint=args.mountpoint,
        name=args.name,
    ))


def decrypt_blob(blob, argv):
    parser = _get_unseal_parser()
    args = parser.parse_args(argv)

    loaded_blob = json.loads(blob)

    mountpoint = loaded_blob['mountpoint']
    if args.mountpoint is not None:
        mountpoint = args.mountpoint
    name = loaded_blob['name']
    if args.name is not None:
        name = args.name

    params = {
        'ciphertext': loaded_blob['ciphertext'],
    }

    path = '/v1/{}/decrypt/{}'.format(mountpoint, name)
    plaintext = _vault_request(path, params, args)['data']['plaintext']
    return base64.b64decode(plaintext)
