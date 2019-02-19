#!/usr/bin/env python

import os
from setuptools import setup
from importlib import import_module


def get_version(package):
    """Print __version__ value from given package __init__ module
    """
    _mod = import_module(package)
    return _mod.__version__


def get_description(filename):
    """Reads and returns content of filegiven file
    """
    with open(os.path.join(os.path.dirname(__file__), filename)) as f:
        return f.read()


setup(
        name='mox-otp',
        packages=[
                'mox_otp',
        ],
        version=get_version('mox_otp'),
        description='Command line tool to query MOX CPU read-only OTP device',
        long_description=get_description('README.md'),
        long_description_content_type='text/markdown',
        url='https://gitlab.labs.nic.cz/turris/mox-otp/',
        author='CZ.NIC, z.s.p.o.',
        author_email='packaging@turris.cz',
        license='GNU GPL v3',
        entry_points={
            'console_scripts': [
                'mox-otp=mox_otp.main:main'
            ]
        },
)
