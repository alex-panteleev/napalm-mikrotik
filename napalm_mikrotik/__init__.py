"""napalm_mikrotik package."""

# Import stdlib
import pkg_resources

# Import local modules
from napalm_mikrotik.mikrotik import MikrotikDriver

try:
    __version__ = pkg_resources.get_distribution('napalm-mikrotik').version
except pkg_resources.DistributionNotFound:
    __version__ = "Not installed"

__all__ = ('MikrotikDriver', )
