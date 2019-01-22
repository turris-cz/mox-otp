#!/usr/bin/python

from sys import argv
from hashlib import sha512
from binascii import hexlify
from struct import pack, unpack

def change_endian(s):
	res = b''
	for i in range(0, len(s), 4):
		res += pack(">I", unpack("<I", s[i:i+4])[0])
	return res

path = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/"
pubkey_path = path + "mox_pubkey"
sign_path = path + "mox_do_sign"

pubkey = open(pubkey_path).read()

if pubkey == "none\n":
	print("no public key burned")
	exit(1)

print("MOX burned public key: %s" % (pubkey,))

if len(argv) < 2:
	print("message not given")
	exit(1)

print("message: %s" % (argv[1],))

h = sha512()
h.update(argv[1].encode("utf-8"))
dig = h.digest()

print("message hash: %s" % (h.hexdigest(),))

s = open(sign_path, "wb")
s.write(change_endian(dig))
s.close()

s = open(sign_path, "rb")
sig = s.read()
s.close()

sig = change_endian(sig)

print("signature: %s" % (hexlify(sig[2:68] + sig[70:]).decode("ascii"),))
