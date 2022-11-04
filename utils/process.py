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
