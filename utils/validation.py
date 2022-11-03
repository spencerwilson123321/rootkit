"""
    This module contains functions for validating command line arguments.
"""


from ipaddress import ip_address, IPv6Address
from psutil import net_if_addrs


def validate_ipv4_address(address: str) -> bool:
    """
        Validates an IPv4 address.

        Parameters
        ----------
        address: str - The IPv4 address to validate.

        Returns
        -------
        bool - True if valid, False if invalid.        
    """
    try:
        ip = ip_address(address)
        if isinstance(ip, IPv6Address):
            return False
        return True
    except:
        return False


def validate_nic_interface(interface: str) -> bool:
    """
        Validates an interface name.

        Checks if the given network interface exists by 
        comparing it to the network interfaces available on 
        the system.

        Parameters
        ----------
        interface: str - The network interface name to validate.

        Returns
        -------
        bool - True if valid, False if invalid. 
    """
    addresses = net_if_addrs()
    if interface in addresses.keys():
        return True
    return False
