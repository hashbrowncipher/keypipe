boto3 = None
try:
    import boto3
except ImportError:
    pass

if boto3 is None:
    raise ImportError("this key provider requires boto3 to operate")

def get_tagline():
    return "Encrypts keys using the Amazon KMS API"

def get_parser_args():
    kwargs = dict(
        help="Generates keys using the Amazon KMS API"
    )
    return tuple(), kwargs


def customize_parser(p):
    p.add_argument('cmk', help='KMS customer master key to use')
    p.set_defaults(func=get_keypair)


def get_keypair(cmk, region_name=None, profile_name=None):
    session = boto3.session.Session(profile_name=profile_name, region_name=region_name)
    kms = session.client('kms')
    key = kms.generate_data_key(
        KeyId=cmk,
        NumberOfBytes=32,
    )

    return key['Plaintext'], key['CiphertextBlob']

def read_blob(blob, cmk=None, region_name=None, profile_name=None):
    session = boto3.session.Session(profile_name=profile_name, region_name=region_name)
    kms = session.client('kms')
    return kms.decrypt(CiphertextBlob=blob)['Plaintext']
