"""
Main entry point of MOX OTP package
"""

import sys
import os

from .argparser import parse_args, hash_type
from .exceptions import MoxOtpApiError, MoxOtpSetupError, MoxOtpUsageError


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
        raise MoxOtpSetupError("sysfs root directory does not exists (probably not running on MOX device)")


def first_line_of_file(filename):
    with open(filename, "r") as f:
        line = f.readline()
    return line.rstrip("\n")


def check_serial():
    try:
        first_line_of_file(SERIAL_PATH)
    except (FileNotFoundError, PermissionError):
        raise MoxOtpApiError("Could not find MOX serial file")


def check_pubkey():
    try:
        pubkey = first_line_of_file(PUBKEY_PATH)
    except (FileNotFoundError, PermissionError):
        raise MoxOtpApiError("Could not find MOX pubkey file")

    if pubkey in ["", "\n", "none\n"]:
        raise MoxOtpSetupError("This device does not have its OTP key generated or accessible")


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
        raise MoxOtpApiError("Could not find MOX sign file")

    return sig[2:68] + sig[70:]


def do_serial():
    """print serial number from OTP
    """
    check_sysfs()
    check_serial()
    print(first_line_of_file(SERIAL_PATH))


def do_pubkey():
    """print public key from OTP
    """
    check_sysfs()
    check_pubkey()
    print(first_line_of_file(PUBKEY_PATH))


def do_sign(inputfile):
    """print signature of given (opened) binary input stream
    """
    check_sysfs()
    check_pubkey()

    dig = count_hash_from_file(inputfile)
    sig = sign_hash(dig)
    print(sig.hex())


def do_sign_hash(hexstr):
    """print signature of given hash
    """
    check_sysfs()
    check_pubkey()

    dig = bytes.fromhex(hexstr)
    sig = sign_hash(dig)
    print(sig.hex())


def main():
    try:
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
            raise MoxOtpUsageError("Unknown command '{}'".format(args.command))

    except MoxOtpUsageError as e:
        errprint("usage error: {}".format(e))
        exit(1)

    except MoxOtpSetupError as e:
        errprint("error: {}".format(e))
        exit(2)

    except MoxOtpApiError as e:
        errprint("sysfs API error: {}".format(e))
        exit(3)


if __name__ == "__main__":
    main()
