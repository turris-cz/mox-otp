"""
Main entry point of MOX OTP package
"""

import sys
import os
import hashlib

from .argparser import parse_args, HASH_TYPE


SYSFS_ROOT = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/"
PUBKEY_PATH = SYSFS_ROOT + "mox_pubkey"
SIGN_PATH = SYSFS_ROOT + "mox_do_sign"
SERIAL_PATH = SYSFS_ROOT + "mox_serial_number"

# number of bytes to read at once
CHUNK_SIZE = 1024
# max number of bytes to read from sysfs sig file
MAX_SIGNATURE_LENGTH = 512


def errprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def check_sysfs():
    if not os.path.isdir(SYSFS_ROOT):
        errprint("sysfs root directory does not exists (probably not running on MOX device)")
        exit(2)


def first_line_of_file(filename):
    with open(filename, "r") as f:
        line = f.readline()
    return line.rstrip("\n")


def check_serial():
    try:
        first_line_of_file(SERIAL_PATH)
    except (FileNotFoundError, PermissionError):
        errprint("The sysfs API is probably broken – could not find MOX serial file")
        exit(3)


def check_pubkey():
    try:
        pubkey = first_line_of_file(PUBKEY_PATH)
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
            s.write(h)
        with open(SIGN_PATH, "rb") as s:
            sig = s.read(MAX_SIGNATURE_LENGTH)
    except (FileNotFoundError, PermissionError):
        errprint("The sysfs API is probably broken – could not find MOX sign file")
        exit(3)

    return sig[2:68] + sig[70:]


def sign_file(f):
    dig = count_hash_from_file(f)
    sig = sign_hash(dig)
    return sig


def do_serial():
    check_sysfs()
    check_serial()
    print(first_line_of_file(SERIAL_PATH))


def do_pubkey():
    check_sysfs()
    check_pubkey()
    print(first_line_of_file(PUBKEY_PATH))


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
    args = parse_args()

    if args.command in ["serial-number", "serial"]:
        do_serial()

    elif args.command in ["public-key", "pubkey", "key"]:
        do_pubkey()

    elif args.command == "sign":
        do_sign(args.infile)

    elif args.command == "sign-hash":
        do_sign_hash(args.hash)

    else:
        errprint("Unknown command '{}'".format(args.command))
        exit(1)


if __name__ == "__main__":
    main()
