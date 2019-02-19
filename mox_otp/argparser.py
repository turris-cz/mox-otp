"""
An argument parser for MOX OTP
"""

import argparse
import sys

from .helpers import hash_type_length

from .__init__ import __version__
from .helpers import HASH_TYPE


def type_hexstr(hexstr):
    """Validate and return hex str
    """

    # check hexstring length
    desired_len = 2*hash_type_length()
    if len(hexstr) != desired_len:
        raise argparse.ArgumentTypeError("Given hash must be exactly {} characters long".format(desired_len))

    # construct bytes from hexstring
    try:
        bytes.fromhex(hexstr)
    except ValueError:
        raise argparse.ArgumentTypeError("Given hash includes non-hexadecimal character")

    return hexstr


def parse_args():
    """Defines argument parser with commands subparsers and return parsed args
    """

    parser = argparse.ArgumentParser(
            description="Command line tool to query MOX CPU read-only OTP device",
    )
    parser.add_argument(
            "-v", "--version",
            action="version",
            version="%(prog)s {}".format(__version__)
    )

    subparsers = parser.add_subparsers(
            # usage format
            title="available subcommands",
            metavar="subcommand",
    )
    # destination variable
    subparsers.required = True
    subparsers.dest = "command"

    sub = subparsers.add_parser(
            "serial-number",
            aliases=["serial"],
            help="Print serial number of the device",
    )

    sub = subparsers.add_parser(
            "public-key",
            aliases=["pubkey", "key"],
            help="Print public key of the device",
    )

    sub = subparsers.add_parser(
            "sign",
            help="Sign given file or standard input if no file is given",
    )
    sub.add_argument(
            'infile',
            help="Input file name (stdin will be used if not given)",
            nargs="?",
            type=argparse.FileType("rb"),
            default=sys.stdin.buffer,
    )

    sub = subparsers.add_parser(
            "sign-hash",
            help="Sign given {} hash; it must include only hexadecimal characters".format(HASH_TYPE),
    )
    sub.add_argument(
            'hash',
            help="A {} hash in hexadecimal form".format(HASH_TYPE),
            type=type_hexstr,
    )

    return parser.parse_args()
