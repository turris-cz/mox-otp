"""
An argument parser for MOX OTP
"""

import argparse


# hash algorithm used for message signature
HASH_TYPE = "sha512"
VERSION="0.1-alpha"



def parse_args():
    """Defines argument parser with commands subparsers and return parsed args
    """

    parser = argparse.ArgumentParser(
            description="Command line tool to query MOX CPU read-only OTP device",
    )
    parser.add_argument(
            "-v", "--version",
            action="version",
            version="%(prog)s {}".format(VERSION)
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
            default=None,
    )

    sub = subparsers.add_parser(
            "sign-hash",
            help="Sign given {} hash; it must include only hexadecimal characters".format(HASH_TYPE),
    )
    sub.add_argument(
            'hash',
            help="A {} hash in hexadecimal form".format(HASH_TYPE),
    )

    return parser.parse_args()
