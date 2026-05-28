#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

"""
sandboxd.py - The server component of sandbox-manager-dist. Handles sandbox
creation, deletion, management, and some forms of IPC.
"""

from pathlib import Path

from .common import SmdCommon

class SandboxdGlobal:
    """
    Global variables for sandboxd.
    """

    ## Readable by all threads, writable by none
    pid_file_path: Path = Path(SmdCommon.state_dir, "pid")

    ## Readable by all threads, writable by main thread
    old_umask: int = 0

    ## TODO: Figure out how multithreading is going to work here; privleapd's
    ## existing structures are likely useful in large part for this, but maybe
    ## not entirely. Some notes:
    ##
    ## * We should have separate main and control threads.
    ## * When a comm socket is destroyed, we should shut down all comm sssions
    ##   associated with it, and shut down all sandboxes associated with the
    ##   user in question.

def main() -> NoReturn:
    """
    Main thread entry point.
    """

    ## Set restrictive umask to prevent any file permission vulnerability
    ## window during socket creation, this denies all privileges for
    ## non-owners.

if __name__ == "__main__":
    main()
