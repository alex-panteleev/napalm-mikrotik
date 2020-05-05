"""NAPALM driver for Mikrotik RouterOS Using SSH"""

from __future__ import unicode_literals

import re
import socket
from collections import defaultdict

# Import NAPALM base
from napalm.base import NetworkDriver
import napalm.base.utils.string_parsers
import napalm.base.constants as C
from napalm.base.helpers import ip as cast_ip
from napalm.base.helpers import mac as cast_mac

# Import NAPALM exceptions
from napalm.base.exceptions import (
    ConnectionException,
    ConnectionClosedException,
)

# Import local modules
from napalm_mikrotik.utils import (
    to_seconds,
    iface_addresses,
    parse_output,
    parse_terse_output,
)


class MikrotikDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor.
        :param hostname:
        :param username:
        :param password:
        :param timeout:
        :param optional_args:
        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'verbose': False,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
            'allow_agent': False,
            'keepalive': 30
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {
            k: optional_args.get(k, v)
            for k, v in netmiko_argument_map.items()
        }

        self.transport = optional_args.get('transport', 'ssh')
        self.port = optional_args.get('port', 22)

        self.changed = False
        self.loaded = False
        self.backup_file = ''
        self.replace = False
        self.merge_candidate = ''
        self.replace_file = ''
        self.profile = ["mikrotik_routeros"]

    def open(self):
        """Open a connection to the device.
        """
        device_type = "mikrotik_routeros"
        if self.transport == "telnet":
            device_type = "mikrotik_routeros_telnet"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection to the device and do the necessary cleanup."""

        self._netmiko_close()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "bad command" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return self._send_command_postprocess(output)
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    @staticmethod
    def _send_command_postprocess(output):
        """
        Cleanup actions on send_command() for NAPALM getters.
        Remove "start/end blank lines"
        """
        return "\n".join(filter(len, output.split('\n')))

    # ok

    def is_alive(self):
        """ Returns a flag with the state of the connection."""
        if self.device is None:
            return {'is_alive': False}
        try:
            if self.transport == 'telnet':
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return {'is_alive': True}
            else:
                # SSH
                # Try sending ASCII null byte to maintain the connection alive
                null = chr(0)
                self.device.write_channel(null)
                return {
                    'is_alive': self.device.remote_conn.transport.is_active()
                }
        except (socket.error, EOFError, OSError):
            # If unable to send, we can tell for sure that the connection is unusable
            return {'is_alive': False}

    def get_interfaces(self):
        """
        Get interface details (last_flapped is not implemented).
        """
        interfaces = {}
        output = self._send_command('/interface print terse')
        if not output:
            return {}

        new_interfaces = parse_terse_output(output)
        for interface in new_interfaces:

            ifname = interface.get('name')

            interfaces.update({
                ifname: {
                    'description': interface.get('comment'),
                    'is_enabled': True if not 'X' in interface.get('_flags') else False,
                    'is_up': True if not 'R' in interface.get('_flags') else False,
                    'last_flapped': -1.0,
                    'mac_address': napalm.base.helpers.mac(interface.get('mac-address')),
                    'speed': -1.0
                }
            })

        return interfaces

    def get_lldp_neighbors(self):
        """
        Return LLDP neighbors simple info.
        Sample output:
        {
            'XGE0/0/1': [
                {
                    'hostname': 'huawei-S5720-01',
                    'port': 'XGE0/0/1'
                },
            'XGE0/0/3': [
                {
                    'hostname': 'huawei-S5720-POE',
                    'port': 'XGE0/0/1'
                },
            'XGE0/0/46': [
                {
                    'hostname': 'Aruba-7210-M',
                    'port': 'GE0/0/2'
                },
            ]
        }
        """
        lldp = {}
        neighbors_detail = self.get_lldp_neighbors_detail()
        for interface, entries in neighbors_detail.items():
            lldp[interface] = []
            for lldp_entry in entries:
                hostname = lldp_entry["remote_system_name"]
                if not hostname:
                    hostname = lldp_entry["remote_chassis_id"]
                lldp[interface].append({
                    "port": lldp_entry["remote_port"],
                    "hostname": hostname
                })

        return lldp

    def get_lldp_neighbors_detail(self, interface=""):
        pass
        """
        Return a detailed view of the LLDP neighbors as a dictionary.
        Sample output:
        {
        'TenGigE0/0/0/8': [
            {
                'parent_interface': u'Bundle-Ether8',
                'remote_chassis_id': u'8c60.4f69.e96c',
                'remote_system_name': u'switch',
                'remote_port': u'Eth2/2/1',
                'remote_port_description': u'Ethernet2/2/1',
                'remote_system_description': u'''huawei os''',
                'remote_system_capab': u'B, R',
                'remote_system_enable_capab': u'B'
            }
        ]
        }
        """
        lldp_neighbors = {}

        output = self._send_command('/ip neighbor print terse')
        if not output:
            return {}

        neighbors = parse_terse_output(output)
        for neighbor in neighbors:

            ifname = neighbor.get('interface')

            if not lldp_neighbors.get(ifname):
                lldp_neighbors[ifname] = list()

            lldp_neighbors[ifname].append({
                'parent_interface': ifname,

                'remote_system_name': neighbor.get('identity'),
                'remote_port': neighbor.get('interface-name'),
                'remote_chassis_id': neighbor.get('mac-address'),

                'remote_system_description': neighbor.get('platform'),
                'remote_system_capab': neighbor.get('system-caps'),
                'remote_system_enable_capab': neighbor.get('system-caps-enabled'),
            })

        return lldp_neighbors

    def get_config(self, retrieve="all", full=False):
        """
        Get config from device.
        Returns the running configuration as dictionary.
        The candidate and startup are always empty string for now
        """

        running_config = self._send_command('/export')

        return {
            'startup': '',
            'running': running_config,
            'candidate': ''
        }

    def get_environment(self):
        """
        Return environment details.
        Sample output:
        {
            "cpu": {
                "0": {
                    "%usage": 18.0
                }
            },
            "fans": {
                "FAN1": {
                    "status": true
                }
            },
            "memory": {
                "available_ram": 3884224,
                "used_ram": 784552
            },
            "power": {
                "PWR1": {
                    "capacity": 600.0,
                    "output": 92.0,
                    "status": true
                }
            },
            "temperature": {
                "CPU": {
                    "is_alert": false,
                    "is_critical": false,
                    "temperature": 45.0
                }
            }
        }
        """
        environment = {}

        system_health = self._send_command('/system health print')
        system_resources = self._send_command('/system resource print')

        for key, value in parse_output(system_health).items():
            if 'fan' in key:
                environment.setdefault('fan', {}).setdefault(re.sub(r'(fan\d+).*', r'\1', key), {
                    'status': True
                })

            if 'temperature' in key:
                environment.setdefault('temperature', {}).setdefault(re.sub(r'(\w+)-temperature(\d+)?.*', r'\1\2', key), {
                    'temperature': float(value.replace('C', '')),
                    'is_alert': False,
                    'is_critical': False,
                })

            if 'psu' in key and 'voltage' in key:
                environment.setdefault('power', {}).setdefault(re.sub(r'psu(\d+)?.*', r'psu\1', key), {
                    'status': True,
                })

        resources = parse_output(system_resources)

        if resources.get('cpu-load'):
            environment.setdefault('cpu', {}).setdefault(
                '0', {'%usage': value.replace('%', resources.get('cpu-load'))})

        return environment

    def get_facts(self):
        system_resource_output = self._send_command(
            '/system resource print')
        system_identity_output = self._send_command(
            '/system identity print')
        system_routerboard_output = self._send_command(
            '/system routerboard print')

        identity = parse_output(system_identity_output)
        resource = parse_output(system_resource_output)
        routerboard = parse_output(system_routerboard_output)

        interface_list = napalm.base.utils.string_parsers.sorted_nicely(
            tuple(self.get_interfaces().keys()))

        return {
            'uptime': to_seconds(resource.get('uptime')),
            'vendor': resource.get('platform'),
            'model': resource.get('board-name'),
            'hostname': identity.get('name'),
            'fqdn': u'',
            'os_version': resource.get('version'),
            'serial_number': routerboard.get('serial-number', ''),
            'interface_list': interface_list,
        }

    def get_interfaces_ip(self):
        """
        Get interface IP details. Returns a dictionary of dictionaries.
        Sample output:
        {
            "LoopBack0": {
                "ipv4": {
                    "192.168.0.9": {
                        "prefix_length": 32
                    }
                }
            },
            "Vlanif2000": {
                "ipv4": {
                    "192.168.200.3": {
                        "prefix_length": 24
                    },
                    "192.168.200.6": {
                        "prefix_length": 24
                    },
                    "192.168.200.8": {
                        "prefix_length": 24
                    }
                },
                "ipv6": {
                    "FC00::1": {
                        "prefix_length": 64
                    }
                }
            }
        }
        """

        interfaces_ip = dict()
        ip_address_output_v4 = self._send_command(
            '/ip address print terse')

        ip_addresses = parse_terse_output(ip_address_output_v4)

        for ip_address in ip_addresses:

            interface = ip_address.get('interface')
            address, mask = ip_address.get('address').split('/')

            interfaces_ip.setdefault(interface, {}) \
                .setdefault('ipv4', {}) \
                .setdefault(address, {}) \
                .setdefault('prefix_length', mask)

        return interfaces_ip

    def get_arp_table(self, vrf=""):
        """
        Get arp table information.
        Return a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float) (not support)
        Sample output:
            [
                {
                    'interface' : 'ether1',
                    'mac'       : '5c:5e:ab:da:3c:f0',
                    'ip'        : '172.17.17.1',
                    'age'       : -1
                },
                {
                    'interface': 'ether1',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '172.17.17.2',
                    'age'       : -1
                }
            ]
        """

        arp_table = []
        output = self._send_command('/ip arp print terse')

        arps = parse_terse_output(output)

        for arp in arps:
            if arp.get('mac-address'):
                arp_table.append({
                    'interface': arp.get('interface'),
                    'mac': napalm.base.helpers.mac(arp.get('mac-address')),
                    'ip': arp.get('address'),
                    'age': -1.0,
                })

        return arp_table

    def get_snmp_information(self):
        """
        Returns a dict of dicts containing SNMP configuration.
        Each inner dictionary contains these fields
            * chassis_id (string)
            * community (dictionary)
            * contact (string)
            * location (string)
        'community' is a dictionary with community string specific information, as follows:
            * acl (string) # acl number or name
            * mode (string) # read-write (rw), read-only (ro)
        Example::
            {
                'chassis_id': u'Asset Tag 54670',
                'community': {
                    u'private': {
                        'acl': u'12',
                        'mode': u'rw'
                    },
                    u'public': {
                        'acl': u'11',
                        'mode': u'ro'
                    },
                    u'public_named_acl': {
                        'acl': u'ALLOW-SNMP-ACL',
                        'mode': u'ro'
                    },
                    u'public_no_acl': {
                        'acl': u'N/A',
                        'mode': u'ro'
                    }
                },
                'contact' : u'Joe Smith',
                'location': u'123 Anytown USA Rack 404'
            }
        """

        snmp_output = self._send_command('/snmp print')
        snmp_community_output = self._send_command(
            '/snmp community print terse')

        snmp = parse_output(snmp_output)
        community_list = parse_terse_output(snmp_community_output)

        community = {}

        for item in community_list:
            community.setdefault(item.get('name'), {
                'acl': item.get('addresses'),
                'mode': u'rw' if item.get('write-access') == 'yes' else u'ro'
            })

        return {
            'contact': snmp.get('contact'),
            'location': snmp.get('location'),
            'community': community,
            'chassis_id': ''
        }

    def get_mac_address_table(self):
        """
        Return the MAC address table.
        Sample output:
        [
            {
                "active": true,
                "interface": "10GE1/0/1",
                "last_move": -1.0,
                "mac": "00:00:00:00:00:33",
                "moves": -1,
                "static": false,
                "vlan": 100
            },
            {
                "active": false,
                "interface": "10GE1/0/2",
                "last_move": -1.0,
                "mac": "00:00:00:00:00:01",
                "moves": -1,
                "static": true,
                "vlan": 200
            }
        ]
        """

        mac_address_table = []
        command = '/interface bridge host print terse'

        output = self._send_command(command)

        for host in parse_terse_output(output):
            mac_address_table.append({
                'mac': napalm.base.helpers.mac(host.get('mac-address')),
                'interface': host.get('interface'),
                'vlan': -1,
                'static': True if not 'D' in host.get('_flags') else False,
                'active': True if not 'X' in host.get('_flags') else False,
                'moves': -1,
                'last_move': -1.0
            })

        return mac_address_table
