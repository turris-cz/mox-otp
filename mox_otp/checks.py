"""
Internal checks for MOX OTP package
"""

import os
from functools import wraps

from .exceptions import MoxOtpApiError, MoxOtpSetupError
from .helpers import first_line_of_file

from .__init__ import MAC_PATH, PUBKEY_PATH, SERIAL_PATH, SYSFS_ROOT


def check_sysfs():
    if not os.path.isdir(SYSFS_ROOT):
        raise MoxOtpSetupError("sysfs root directory does not exists (probably not running on MOX device)")


def check_serial(f):
    @wraps(f)
    def _checked(*args, **kwargs):
        check_sysfs()
        try:
            first_line_of_file(SERIAL_PATH)
        except (FileNotFoundError, PermissionError):
            raise MoxOtpApiError("Could not find MOX serial file")
        return f(*args, **kwargs)

    return _checked


def check_mac(f):
    @wraps(f)
    def _checked(*args, **kwargs):
        check_sysfs()
        try:
            first_line_of_file(MAC_PATH)
        except (FileNotFoundError, PermissionError):
            raise MoxOtpApiError("Could not find MOX MAC address file")
        return f(*args, **kwargs)

    return _checked


def check_pubkey(f):
    @wraps(f)
    def _checked(*args, **kwargs):
        check_sysfs()
        try:
            pubkey = first_line_of_file(PUBKEY_PATH)
        except (FileNotFoundError, PermissionError):
            raise MoxOtpApiError("Could not find MOX pubkey file")

        if pubkey in ["", "\n", "none\n"]:
            raise MoxOtpSetupError("This device does not have its OTP key generated or accessible")

        return f(*args, **kwargs)

    return _checked
