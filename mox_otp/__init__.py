"""
MOX OTP python package
"""

import os

__version__ = '0.3.1'


# hash algorithm used for message signature
HASH_TYPE = "sha512"

# Paths to kernel sysfs API
# In upstream kernel the path changed to /sys/firmware/turris-mox-rwtm
# and files lost the "mox_" prefix
SYSFS_ROOT_NEW = "/sys/firmware/turris-mox-rwtm"
DEBUGFS_ROOT_NEW = "/sys/kernel/debug/turris-mox-rwtm"
SYSFS_ROOT_OLD = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0"

if os.path.isdir(SYSFS_ROOT_NEW):
    SYSFS_ROOT = SYSFS_ROOT_NEW
    PUBKEY_FILENAME = "pubkey"
    SERIAL_FILENAME = "serial_number"
    MAC_FILENAME = "mac_address1"
else:
    SYSFS_ROOT = SYSFS_ROOT_OLD
    PUBKEY_FILENAME = "mox_pubkey"
    SERIAL_FILENAME = "mox_serial_number"
    MAC_FILENAME = "mox_mac_address1"

if os.path.isdir(DEBUGFS_ROOT_NEW):
    DEBUGFS_ROOT = DEBUGFS_ROOT_NEW
    SIGN_FILENAME = "do_sign"
else:
    DEBUGFS_ROOT = SYSFS_ROOT_OLD
    SIGN_FILENAME = "mox_do_sign"


PUBKEY_PATH = os.path.join(SYSFS_ROOT, PUBKEY_FILENAME)
SIGN_PATH = os.path.join(DEBUGFS_ROOT, SIGN_FILENAME)
SERIAL_PATH = os.path.join(SYSFS_ROOT, SERIAL_FILENAME)
MAC_PATH = os.path.join(SYSFS_ROOT, MAC_FILENAME)
