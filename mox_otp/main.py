#!/usr/bin/env python3

import sys
from hashlib import sha512
from struct import pack, unpack


SYSFS_ROOT = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/"
PUBKEY_PATH = SYSFS_ROOT + "mox_pubkey"
SIGN_PATH = SYSFS_ROOT + "mox_do_sign"

# max number of bytes to read from sysfs sig file
MAX_SIGNATURE_LENGTH = 512


def errprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def change_endian(s):
    res = b''
    for i in range(0, len(s), 4):
        res += pack(">I", unpack("<I", s[i:i+4])[0])
    return res


def check_pubkey():
    try:
        with open(PUBKEY_PATH, "r") as f:
            pubkey = f.readline()
    except (FileNotFoundError, PermissionError):
        errprint("Could not find MOX pubkey file (probably not running on MOX device)")
        exit(2)

    if pubkey in ["", "\n", "none\n"]:
        errprint("This device does not have its OTP key generated or accessible")
        exit(2)


def sign_message(message):
    h = sha512()
    h.update(bytes(message, encoding="utf-8"))
    dig = h.digest()

    try:
        with open(SIGN_PATH, "wb") as s:
            s.write(change_endian(dig))
        with open(SIGN_PATH, "rb") as s:
            sig = change_endian(s.read(MAX_SIGNATURE_LENGTH))
    except (FileNotFoundError, PermissionError):
        errprint("Could not find MOX sign file – the sysfs API is probably broken")
        exit(3)

    print((sig[2:68] + sig[70:]).hex())


def main():
    check_pubkey()

    if len(sys.argv) < 2:
        print("message not given")
        exit(1)

    message = sys.argv[1]
    sign_message(message)


if __name__ == "__main__":
    main()
