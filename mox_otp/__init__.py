"""
MOX OTP python package
"""

__version__ = '0.2'


# hash algorithm used for message signature
HASH_TYPE = "sha512"

# Paths to kernel sysfs API
SYSFS_ROOT = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/"
PUBKEY_PATH = SYSFS_ROOT + "mox_pubkey"
SIGN_PATH = SYSFS_ROOT + "mox_do_sign"
SERIAL_PATH = SYSFS_ROOT + "mox_serial_number"
MAC_PATH = SYSFS_ROOT + "mox_mac_address1"
