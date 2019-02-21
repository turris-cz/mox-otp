"""
Helper functions for MOX OTP package
"""

import hashlib
import sys

from .exceptions import MoxOtpSetupError

from .__init__ import HASH_TYPE


def errprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def first_line_of_file(filename):
    with open(filename, "r") as f:
        line = f.readline()
    return line.rstrip("\n")


def hash_type():
    """Returns constructed hash of HASH_TYPE
    """
    try:
        h = hashlib.new(HASH_TYPE)
    except ValueError:
        raise MoxOtpSetupError("Hash type {} is not available".format(HASH_TYPE))

    return h


def hash_type_length():
    """Returns number of bytes for HASH_TYPE
    """
    h = hash_type()
    return h.digest_size
