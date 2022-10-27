"""
    This module exports a single function to set the process
    name.
"""

from setproctitle import setproctitle

def hide_process_name(name: str):
    """
        
    
    """
    setproctitle(name)
