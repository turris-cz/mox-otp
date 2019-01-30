#!/usr/bin/env python3

import sys
from hashlib import sha512
from struct import pack, unpack


SYSFS_ROOT = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/"
PUBKEY_PATH = SYSFS_ROOT + "mox_pubkey"
SIGN_PATH = SYSFS_ROOT + "mox_do_sign"


def change_endian(s):
    res = b''
    for i in range(0, len(s), 4):
        res += pack(">I", unpack("<I", s[i:i+4])[0])
    return res


def main():
    pubkey = open(PUBKEY_PATH).read()

    if pubkey == "none\n":
        print("no public key burned")
        exit(1)

    print("MOX burned public key: {}".format(pubkey))

    if len(sys.argv) < 2:
        print("message not given")
        exit(1)

    message = sys.argv[1]
    print("message: {}".format(message))

    h = sha512()
    h.update(bytes(message, encoding='utf-8'))
    dig = h.digest()

    print("message hash: {}".format(h.hexdigest()))

    s = open(SIGN_PATH, "wb")
    s.write(change_endian(dig))
    s.close()

    s = open(SIGN_PATH, "rb")
    sig = s.read()
    s.close()

    sig = change_endian(sig)

    print("signature: {}".format((sig[2:68] + sig[70:]).hex()))


if __name__ == "__main__":
    main()
