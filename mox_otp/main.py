"""
Main entry point of MOX OTP package
"""

import sys

from .argparser import parse_args
from .checks import check_mac, check_serial, check_pubkey
from .exceptions import MoxOtpApiError, MoxOtpSetupError, MoxOtpUsageError
from .helpers import errprint, first_line_of_file, hash_type


from .checks import MAC_PATH, PUBKEY_PATH, SERIAL_PATH, SIGN_PATH


# number of bytes to read at once
CHUNK_SIZE = 1024
# max number of bytes to read from sysfs sig file
MAX_SIGNATURE_LENGTH = 512


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


@check_serial
def do_serial():
    """print serial number from OTP
    """
    print(first_line_of_file(SERIAL_PATH))


@check_mac
def do_mac():
    """print MAC address from OTP
    """
    print(first_line_of_file(MAC_PATH))


@check_pubkey
def do_pubkey():
    """print public key from OTP
    """
    print(first_line_of_file(PUBKEY_PATH))


@check_pubkey
def do_sign(inputfile):
    """print signature of given (opened) binary input stream
    """
    dig = count_hash_from_file(inputfile)
    sig = sign_hash(dig)
    print(sig.hex())


@check_pubkey
def do_sign_hash(hexstr):
    """print signature of given hash
    """
    dig = bytes.fromhex(hexstr)
    sig = sign_hash(dig)
    print(sig.hex())


def main():
    try:
        args = parse_args()

        if args.command in ["serial-number", "serial"]:
            do_serial()

        elif args.command in ["mac-address", "mac"]:
            do_mac()

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
