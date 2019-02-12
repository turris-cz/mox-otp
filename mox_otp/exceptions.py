"""
MOX OTP exceptions
"""


class MoxOtpError(Exception):
    pass

class MoxOtpUsageError(MoxOtpError):
    pass

class MoxOtpSetupError(MoxOtpError):
    pass

class MoxOtpApiError(MoxOtpError):
    pass
