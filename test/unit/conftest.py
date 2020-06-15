"""Test fixtures."""
from builtins import super

import pytest
from napalm.base.test import conftest as parent_conftest

from napalm.base.test.double import BaseTestDouble

from napalm_mikrotik import mikrotik


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = mikrotik.MikrotikDriver
    request.cls.patched_driver = PatchedMikrotikDriver
    request.cls.vendor = 'mikrotik'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedMikrotikDriver(mikrotik.MikrotikDriver):
    """Patched Mikrotik Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Patched Mikrotik Driver constructor."""
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['device']
        self.device = FakeMikrotikDevice()

    def disconnect(self):
        pass

    def is_alive(self):
        return {
            'is_alive': True  # In testing everything works..
        }

    def open(self):
        pass


class FakeMikrotikDevice(BaseTestDouble):
    """Mikrotik device test double."""

    def send_command(self, command, **kwargs):
        # cmd = re.sub(r'[\[\]\*\^\+\s\|/]', '_', command)
        filename = '{}.txt'.format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return str(result)
