import boto3


def get_parser_args():
    kwargs = dict(
        help="Generates keys using the Amazon KMS API"
    )
    return tuple(), kwargs


def customize_parser(p):
    p.add_argument('cmk', help='KMS customer master key to use')
    p.set_defaults(func=get_keypair)


def get_keypair(args):
    kms = boto3.client('kms')
    key = kms.generate_data_key(
        KeyId=args.cmk,
        KeySpec='AES_256',
    )

    return (key['Plaintext'], key['CiphertextBlob'])


def decrypt_blob(blob):
    kms = boto3.client('kms')
    return kms.decrypt(CiphertextBlob=blob)['Plaintext']
