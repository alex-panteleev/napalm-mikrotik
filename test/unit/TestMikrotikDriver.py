import unittest

from napalm_mikrotik import mikrotik
from napalm.base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver  # noqa


class TestConfigMikrotikDriver(unittest.TestCase, TestConfigNetworkDriver):

    @classmethod
    def setUpClass(cls):
        """Executed when the class is instantiated."""
        cls.vendor = 'mikrotik'
        cls.device = mikrotik.MikrotikDriver(
            '127.0.0.1',
            'vagrant',
            'vagrant',
            timeout=60,
            optional_args={
                'port': 22,
            },
        )
        cls.device.open()
