#!/usr/bin/env python3

import sys
import os
import hashlib
from struct import pack, unpack


VERSION="0.1-alpha"

SYSFS_ROOT = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/"
PUBKEY_PATH = SYSFS_ROOT + "mox_pubkey"
SIGN_PATH = SYSFS_ROOT + "mox_do_sign"

# number of bytes to read at once
CHUNK_SIZE = 1024
# hash algorithm used for message signature
HASH_TYPE = "sha512"
# max number of bytes to read from sysfs sig file
MAX_SIGNATURE_LENGTH = 512

SCRIPTNAME="mox-otp"
USAGE="""USAGE
    General syntax:
        {0} command [args..]

    Available commands:
        {0} help
                    Print this message end exits

        {0} version
                    Print script version and exits

        {0} sign [file]
                    Sign given file or standard input if no file is given

        {0} sign-hash hash
                    Sign given {1} hash; it must include only hexadecimal characters
""".format(SCRIPTNAME, HASH_TYPE)


def errprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def change_endian(s):
    res = b''
    for i in range(0, len(s), 4):
        res += pack(">I", unpack("<I", s[i:i+4])[0])
    return res


def check_sysfs():
    if not os.path.isdir(SYSFS_ROOT):
        errprint("sysfs root directory does not exists (probably not running on MOX device)")
        exit(2)


def check_pubkey():
    try:
        with open(PUBKEY_PATH, "r") as f:
            pubkey = f.readline()
    except (FileNotFoundError, PermissionError):
        errprint("The sysfs API is probably broken – could not find MOX pubkey file")
        exit(3)

    if pubkey in ["", "\n", "none\n"]:
        errprint("This device does not have its OTP key generated or accessible")
        exit(2)


def hash_type():
    """Returns constructed hash of HASH_TYPE
    """
    try:
        h = hashlib.new(HASH_TYPE)
    except ValueError:
        errprint("Hash type {} is not available".HASH_TYPE)
        exit(3)

    return h


def hash_type_length():
    """Returns number of bytes for HASH_TYPE
    """
    h = hash_type()
    return h.digest_size


def count_hash_from_file(f):
    """f is opened file for reading in binary mode
    """
    h = hash_type()

    for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
        h.update(chunk)

    return h.digest()


def sign_hash(h):
    """h must be bytes processed with HASH_TYPE algorithm
    """
    try:
        with open(SIGN_PATH, "wb") as s:
            s.write(change_endian(h))
        with open(SIGN_PATH, "rb") as s:
            sig = change_endian(s.read(MAX_SIGNATURE_LENGTH))
    except (FileNotFoundError, PermissionError):
        errprint("The sysfs API is probably broken – could not find MOX sign file")
        exit(3)

    return sig[2:68] + sig[70:]


def sign_file(f):
    dig = count_hash_from_file(f)
    sig = sign_hash(dig)
    return sig


def do_sign(filename=None):
    check_sysfs()
    check_pubkey()

    if not filename:
        sig = sign_file(sys.stdin.buffer)
    else:
        try:
            with open(filename, "rb") as f:
                sig = sign_file(f)
        except IsADirectoryError:
            errprint("'{}' is a directory".format(filename))
            exit(1)
        except (FileNotFoundError, PermissionError):
            errprint("File '{}' does not exists or is not readable".format(filename))
            exit(1)

    print(sig.hex())


def do_sign_hash(hex_digest):
    check_sysfs()
    check_pubkey()

    # check hexstring length
    desired_len = 2*hash_type_length()
    if len(hex_digest) != desired_len:
        errprint("Given hash must be exactly {} characters long".format(desired_len))
        exit(1)

    # construct bytes from hexstring
    try:
        dig = bytes.fromhex(hex_digest)
    except ValueError:
        errprint("Given hash includes non-hexadecimal character")
        exit(1)

    # sign the hash
    sig = sign_hash(dig)
    print(sig.hex())


def main():
    if len(sys.argv) < 2:
        errprint("No command was passed")
        errprint(USAGE)
        exit(1)

    command = sys.argv[1]
    if command == "help":
        print(USAGE)

    elif command == "version":
        print(VERSION)

    elif command == "sign":
        if len(sys.argv) == 2:
            # sign the stdin
            do_sign()
        elif len(sys.argv) == 3:
            # sign the given file
            do_sign(sys.argv[2])
        else:
            errprint("Too many arguments for command `sign`")
            exit(1)

    elif command == "sign-hash":
        if not len(sys.argv) == 3:
            errprint("`sign-hash` needs exactly one argument")
            exit(1)
        do_sign_hash(sys.argv[2])

    else:
        errprint("Unknown command '{}'".format(command))
        errprint(USAGE)
        exit(1)


if __name__ == "__main__":
    main()
