import struct

INITIAL_HEADER_FORMAT='!3sB64s32sB'
INITIAL_HEADER_SIZE = struct.calcsize(INITIAL_HEADER_FORMAT)

PROVIDER_HEADER_FORMAT = '!BH'
PROVIDER_HEADER_SIZE = struct.calcsize(PROVIDER_HEADER_FORMAT)

MAGIC = b'AE|'
VERSION = 1

def _serialize_provider_header(name, blob):
    encoded_name = name.encode('ascii')
    lengths = struct.pack(PROVIDER_HEADER_FORMAT,
        len(encoded_name),
        len(blob)
    )
    return lengths + encoded_name + blob

def serialize(salt, checksum, provider_blobs):
    serialized_blobs = [
        _serialize_provider_header(name, blob) for (name, blob) in 
        sorted(provider_blobs.items())
    ]
    num_blobs = len(serialized_blobs)
    packed = struct.pack(INITIAL_HEADER_FORMAT,
        MAGIC,
        VERSION,
        salt,
        checksum,
        num_blobs,
    )
    return packed + b''.join(serialized_blobs)

def cut(s, p):
    return s[:p], s[p:]

def _deserialize_all_provider_info(num_blobs, next_header, infile):
    for num_blobs in range(num_blobs, 0, -1):
        name_len, blob_len = struct.unpack(
            PROVIDER_HEADER_FORMAT,
            next_header
        )
        provider_info_len = name_len + blob_len
        to_read = provider_info_len
        if num_blobs > 1:
            to_read += INITIAL_HEADER_SIZE
        d = infile.read(to_read)
        provider_info, next_header = cut(d, provider_info_len)
        name, blob = cut(d, name_len)
        yield name.decode('ascii'), blob

def deserialize(infile):
    wanted_bytes = INITIAL_HEADER_SIZE + PROVIDER_HEADER_SIZE
    initial_input = infile.read(wanted_bytes)
    if len(initial_input) != wanted_bytes:
        raise InsufficientDataError

    initial_header, next_header = cut(initial_input, INITIAL_HEADER_SIZE)
    d = struct.unpack(INITIAL_HEADER_FORMAT, initial_header)
    magic, version, salt, checksum, num_blobs = d
    if magic != MAGIC:
        raise UnrecognizedMagicError

    if version != VERSION:
        raise UnrecognizedVersionError

    g = _deserialize_all_provider_info(num_blobs, next_header, infile)
    return salt, checksum, g
