aepipe: a pipe-oriented authenticated encryptor
===============================================

.. image:: https://img.shields.io/coverity/scan/10638.svg
    :target: https://scan.coverity.com/projects/hashbrowncipher-keypipe
    :alt: Coverity Scan Build Status

.. image:: https://travis-ci.org/hashbrowncipher/keypipe.svg?branch=master
    :target: https://travis-ci.org/hashbrowncipher/keypipe
    :alt: Travis-CI Build Status

aepipe uses AES-GCM to perform authenticated encryption on pipes, providing
confidentiality and authenticity.

.. contents:: **Table of Contents**

What is authenticated encryption?
---------------------------------

Authenticated encryption (AE) combines encryption, which guarantees a message is
confidential, with authentication, which guarantees that a message has not been
corrupted or tampered with. In general, raw encryption (such as with AES) does
not provide message authentication. And message authentication never provides
confidentiality.

aepipe uses 256-bit AES-GCM to perform authenticated encryption. It may support
other algorithms in the future.

What does this software provide?
--------------------------------

aepipe provides a C shared library for performing AE. It is pipe-oriented,
meaning the library primitives expect to read data from an input pipe and write
the resulting output to an output pipe. It is especially useful for situations
where data is transferred in a streaming fashion, and maximum performance is
desired.

Why not use...
~~~~~~~~~~~~~~

**gpg**

gpg provides a variant of authenticated encryption that encrypts a SHA-1 hash
which has been concatenated to the plaintext. This violates the `cryptographic
doom principle <https://moxie.org/blog/the-cryptographic-doom-principle/>`_.
Worse, the command line tool outputs corrupted data, and only later warns the
user.

::

  $ key=4d8ec20204895b1b875ad2c8a68a06f488c10ffb57b511c0deefc3e6f46dd7c9
  $ echo $key | xxd -p -r > passphrase
  $ dd if=/dev/zero bs=1M count=1 | gpg --symmetric --no-use-agent --passphrase-file passphrase \
    --cipher-algo AES256 -z0 > /dev/null
  $ tr 'N' 'a' < output | gpg --decrypt --no-use-agent --passphrase-file passphrase | xxd
  Reading passphrase from file descriptor 3
  gpg: AES256 encrypted data
  gpg: encrypted with 1 passphrase
  00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  00000040: 0000 002f 0000 9735 21db a97d babb aba8  .../...5!..}....
  00000050: 1f39 cbc1 241c 0000 0000 0000 0000 0000  .9..$...........
  ...
  gpg: [don't know]: invalid packet (ctb=00)
  gpg: WARNING: encrypted message has been manipulated!
  gpg: [don't know]: invalid packet (ctb=00)
  $ gpg --version | head -n2
  gpg (GnuPG) 1.4.20
  Copyright (C) 2015 Free Software Foundation, Inc.

It's also very slow:

::

  $ dd if=/dev/zero bs=1M count=4096 | gpg --symmetric --no-use-agent --passphrase-file passphrase \
    --cipher-algo AES256 -z0 > /dev/null
  Reading passphrase from file descriptor 3
  4096+0 records in
  4096+0 records out
  4294967296 bytes (4.3 GB, 4.0 GiB) copied, 56.0622 s, 76.6 MB/s

**openssl enc**

openssl enc provides encryption but not authentication. It is fast, reaching
1GB/sec easily. Its key derivation algorithm does `leave much to be desired
<http://crypto.stackexchange.com/questions/3298/is-there-a-standard-for-openssl-interoperable-aes-encryption/35614#35614>`_.

Command-line usage
------------------

Usage
~~~~~

::

  $ ./aepipe
  Usage: ./aepipe [-d] <keyfile>

  Always check the return code!
  Nonzero means corrupted or partial data.

Encryption
~~~~~~~~~~

To encrypt data, we first read from /dev/urandom to generate a unique key for
this operation. Uniqueness of keys is of paramount importance to the encryption
operation. aepipe reads its 32 byte key from a file. In this case we've used
bash command substitution as an alternative to writing the key to the
filesystem. Note that in a real world use-case, it is unwise to disclose $key.

::

  $ key=$(dd if=/dev/urandom bs=32 count=1 | xxd -p | tr -d '\n')
  $ echo $key
  4d8ec20204895b1b875ad2c8a68a06f488c10ffb57b511c0deefc3e6f46dd7c9
  $ ./aepipe <(echo $key | xxd -p -r) <<EOF > encrypted
  > this is my data
  > please seal it up safe
  EOF
  $ xxd encrypted
  00000000: 0000 0000 0000 0000 66c6 978c f350 475b  ........f....PG[
  00000010: bef3 f100 adb6 05fb 0000 0027 c2c8 074e  ...........'...N
  00000020: 8961 d397 7dc9 4835 c5bd 96ba 8b49 88e2  .a..}.H5.....I..
  00000030: fd46 7056 55bf 71b4 03d0 8171 df1f 298e  .FpVU.q....q..).
  00000040: a8ae 7af2 e256 f864 94fa 3c1f 5fdf 8844  ..z..V.d..<._..D
  00000050: 5610 2400 0000 00                        V.$....

Decryption
~~~~~~~~~~

The decryption operation produces our original input for us.

::

  $ aepipe -d <(echo $key | xxd -p -r) < encrypted
  this is my data
  please seal it up safe
  $ echo $?
  0

Decryption of corrupted data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

During decryption, aepipe will refuse to output data that does not authenticate
correctly. Instead, it will exit with a nonzero status code. Here we replace al
instances of the character 'N' in the encrypted file with 'a'::

  $ tr 'N' 'a' < encrypted | aepipe -d <(echo $key | xxd -p -r)
  Input data was corrupt
  $ echo $?
  1

What if the data is truncated? aepipe will output data up until the vicinity of
the truncation, and then print an error message to standard error. It will also
exit with a non-zero return code.

::

  $ dd if=encrypted bs=83 count=1 status=none | aepipe -d <(echo $key | xxd -p -r)
  this is my data
  please seal it up safe
  Input data was corrupt
  $ echo $?
  1

Additional bytes truncated from the input will eventually remove all bytes from
the output::

  $ dd if=encrypted bs=66 count=1 status=none | ./aepipe -d <(echo $key | xxd -p -r)
  Input data was corrupt
  $ echo $?
  1

What are the goals of this tool?
---------------------------------

I developed this software because I could not find a high-performance
authenticated encryption tool capable of streaming output.

The goals envisioned in its design are:

security of data
  (see `Threat model`_, below)

streaming
  aepipe authenticates data in chunks, emitting output as it makes progress
  through the stream. As a result, it is never necessary to temporarily store or
  spool more than a single chunk (typically 1MB) while the data waits for
  authentication.

performance
  aepipe is designed to operate as efficiently as possible, and
  make use of the maximum performance provided by the underlying hardware. >1
  gigabyte per second is typical on modern hardware.

simplicity
   aepipe does exactly as much cryptography as necessary to get its job done.

minimal dependencies
  aepipe depends only on Linux, libc, and libcrypto (OpenSSL)

maintainability
  the actual encryption algorithms are provided by the dynamically linked
  libcrypto. If a system administrator wishes to change/upgrade libcrypto,
  this can be done without modifying the installation of aepipe.

compatibility
  aepipe communicates exclusively using pipes, which are nearly universally
  understood by other software.

API
---

aepipe provides a shared library with a simple API. There are Python (cffi)
bindings available as well.

aepipe's contract
-----------------

Do not re-use keys!
~~~~~~~~~~~~~~~~~~~

aepipe's security guarantees are entirely dependent upon the secrecy and
uniqueness of keys used for encryption of data. This is a direct consequence of
how the AES-GCM algorithm works.

This means that one should not EVER:

1. disclose a key that was used to encrypt data with aespipe
2. encrypt data twice with the same key

As an example of what will happen if you encrypt data twice with the same key,
let's consider that we are encrypting the backup of a SQL database with a free
page. Since this page is free, it consists of zeroes. Later on this page gets
filled with important data.

::

  $ key=$(dd if=/dev/urandom bs=32 count=1 | xxd -p | tr -d '\n')
  $ echo $key
  0ba01df8b6a7d618a45dea525b466c01aa8fed2d7f2f27b6ab2b01272ce4a66a
  $ dd if=/dev/zero bs=4096 count=1 | aepipe <(echo $key) > zeropage
  $ aepipe <(echo $key) <<EOF > nonzeropage
  > this is my data
  > but I'm treating it poorly
  > so an attacker will get to it
  > EOF
  $ ./xor zeropage nonzeropage | xxd
  00000000: 0000 0000 0000 0000 fcde eaa0 1652 fb9e  .............R..
  00000010: 9b35 18c2 b7d8 e52f 0000 1049 7468 6973  .5...../...Ithis
  00000020: 2069 7320 6d79 2064 6174 610a 6275 7420   is my data.but
  00000030: 4927 6d20 7472 6561 7469 6e67 2069 7420  I'm treating it
  00000040: 706f 6f72 6c79 0a73 6f20 616e 2061 7474  poorly.so an att
  00000050: 6163 6b65 7220 7769 6c6c 2067 6574 2074  acker will get t
  00000060: 6f20 6974 0a9c 30d0 a3ad 76f3 1e37 6fc0  o it..0...v..7o.
  00000070: f88e 1c51 ffb3 f5fe 39                   ...Q....9
  $ ./xor zeropage nonzeropage | strings
  Ithis is my data
  but I'm treating it poorly
  so an attacker will get to it

Able to compare the old encrypted version side-by-side with the new encrypted
version, the attacker has completely stripped away the confidentiality of the
AES encryption. Other types of attacks are possible as well, but none are as
easy to demonstrate as this. Just say no to reuse of keys!

Threat model
~~~~~~~~~~~~

The aepipe threat model considers an attacker which can:

1. read the encrypted aepipe stream
2. modify, truncate, or transpose any part of that stream
3. append data to the end of an aepipe stream

Faced with such an attacker, aepipe encryption attempts to guarantee:

1. the attacker cannot gain any information from the encrypted stream that they
   did not already know.

aepipe decryption attempts to guarantee:

1. the output stream will be a prefix of the original message data.
2. if the output stream is not the same length as the original message data, the
   aepipe return code will be non-zero

aepipe makes these guarantees based on assumptions about the
correctness and security of the:

1. AES encryption algorithm
2. GCM mode of operation
3. correctness of implementations of the above algorithms in the libcrypto
   library

Note that aepipe decryption makes no guarantee regarding data that is appended
to the end of a stream. This is a feature: users who wish to may append whatever
they please to the end of an aepipe stream.

Data Format
-----------

Specification
~~~~~~~~~~~~~

The format of an encrypted aepipe stream is::

  1 8 byte position counter
  N message blocks (0 < N < 2^64)

A message block consists of::

  1 16 byte authentication tag (T)
  1 4 byte big-endian length field (L)
  L bytes of encrypted data (D)

All aepipe streams have a final message block of length zero (L=0). The aepipe
encryption of a zero length stream is given as an example::

  $ key=$(dd if=/dev/urandom bs=32 count=1 | xxd -p | tr -d '\n')
  $ aepipe <(echo $key | xxd -p -r) < /dev/null | hd
  00000000  00 00 00 00 00 00 00 00  91 71 69 34 8f f5 56 fb  |.........qi4..V.|
  00000010  6a 78 95 d6 8e a6 50 c9  00 00 00 00              |jx....P.....|
  0000001c

Notes
~~~~~

As an implementation detail, aepipe encryption creates message blocks of
1,048,576 bytes (1 megabyte). aepipe decryption will refuse to process message
blocks larger than this size.

The aepipe decryption routine finishes when it reads the final message block.
The current implementation of aepipe decryption will not read any bytes from its
input pipe past the last message block. Users MAY place any bytes they desire in
the input pipe past the last message block. Of course, aepipe makes no guarantee
what those bytes contain.
