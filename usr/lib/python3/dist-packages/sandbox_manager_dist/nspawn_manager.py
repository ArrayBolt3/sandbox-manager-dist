#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught

"""
nspawn_manager.py - The systemd-nspawn interface component of
sandbox-manager-dist. Handles boot, shutdown, and console access. Note that
some of sandbox-manager-dist's more advanced features are implemented using a
sandbox-side agent that it connected to over a UNIX socket; these features do
not go through nspawn_manager.py.
"""

from multiprocessing.connection import Connection

def nspawn_manager_main(
    ctp_pipe: Connection, sandbox_uuid: str, boot_mode: str
) -> None:
    """
    Entry point for nspawn_manager.py.
    """
