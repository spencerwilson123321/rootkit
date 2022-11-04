"""
    This module exports a single function to set the process
    name.
"""

from setproctitle import setproctitle

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
    setproctitle(name)

def set_proc_name(newname):
    from ctypes import cdll, byref, create_string_buffer
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(newname)+1)
    buff.value = newname
    libc.prctl(15, byref(buff), 0, 0, 0)

