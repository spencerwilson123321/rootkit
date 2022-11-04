"""
    This module exports a single function to set the process
    name.
"""

from setproctitle import setproctitle
import os
import sys
from ctypes import cdll, create_string_buffer, CDLL, c_ulong

def hide_process_name(name: str) -> None:
    """
        Hides the process name by changing the process name to the given name.
        
        Parameters
        ----------
        name - The name to set the process name to.
        
        Returns
        -------
        None
    """
    # setproctitle(name)
    # Get the PID of the process.
    cdll.LoadLibrary("libc.so.6")
    libc = CDLL("libc.so.6")
    pr_set_name = c_ulong(15)
    zero = c_ulong(0)
    newname = bytes("newname", encoding="ascii")
    libc.prctl(pr_set_name, name, zero, zero, zero)
    # libc.strcpy(sys.argv[0], newname.value)
    # print(sys.argv[0])
    # print(newname.value)
