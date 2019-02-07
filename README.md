# MOX OTP

Python library to query MOX CPU cryptographic device (called OTP).

OTP device has permanent read-only memory to store data during production. It
contains information about *serial number*, *MAC address*, etc. It also contains
*ECDSA* private key and have interface to sign 512-bits long message (generally
a *SHA512* hash of any message).

This tool provides comfort command line interface to these features and data.
