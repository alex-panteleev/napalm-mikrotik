"""Tests for getters."""

import pytest
from unittest import SkipTest

from napalm.base.test.getters import BaseTestGetters, wrap_test_cases

@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):

    @wrap_test_cases
    def test_get_config_sanitized(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_config_filtered(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_method_signatures(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_users(self, test_case):
        return self.device.get_users()
    
    @wrap_test_cases
    def test_get_facts(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_lldp_neighbors(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_interfaces_counters(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_environment(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_lldp_neighbors_detail(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_arp_table(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_arp_table_with_vrf(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_interfaces_ip(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_mac_address_table(self, test_case):
        raise SkipTest()

    @wrap_test_cases
    def test_get_snmp_information(self, test_case):
        raise SkipTest()
