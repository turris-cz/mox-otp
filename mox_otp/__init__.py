"""
MOX OTP python package
"""

import os

__version__ = '0.2'


# hash algorithm used for message signature
HASH_TYPE = "sha512"

# Paths to kernel sysfs API
# In upstream kernel the path changed to /sys/firmware/turris-mox-rwtm
# and files lost the "mox_" prefix
SYSFS_ROOT_NEW = "/sys/firmware/turris-mox-rwtm/"
SYSFS_ROOT_OLD = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/"
if os.path.isdir(SYSFS_ROOT_NEW):
    SYSFS_ROOT = SYSFS_ROOT_NEW
    PUBKEY_PATH = SYSFS_ROOT + "pubkey"
    SIGN_PATH = SYSFS_ROOT + "do_sign"
    SERIAL_PATH = SYSFS_ROOT + "serial_number"
    MAC_PATH = SYSFS_ROOT + "mac_address1"
else:
    SYSFS_ROOT = SYSFS_ROOT_OLD
    PUBKEY_PATH = SYSFS_ROOT + "mox_pubkey"
    SIGN_PATH = SYSFS_ROOT + "mox_do_sign"
    SERIAL_PATH = SYSFS_ROOT + "mox_serial_number"
    MAC_PATH = SYSFS_ROOT + "mox_mac_address1"
