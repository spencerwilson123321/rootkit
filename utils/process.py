"""
    This module exports a single function to set the process
    name.
"""

from setproctitle import setproctitle
import os
import sys
from ctypes import cdll, create_string_buffer

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
    clib = cdll.msvcrt
    newname = create_string_buffer("newname\0")
    clib.strcrpy(sys.argv[0], newname)
