#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, duplicate-code

"""
delete_handler.py - Delete sandboxes.
"""

import os
import shutil
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from .common import (
    SmdCommon,
    SmdSandboxState,
)

from .protocol import (
    SmdCommServerDeleteSuccessMsg,
    SmdCommServerDeleteFailedMsg,
)

def delete_handler_main(child_pipe: Connection) -> None:
    """
    Entry point for delete_handler.py.
    """

    ## Set restrictive umask to ensure sandbox files are only accessible by
    ## root.
    os.umask(0o077)

    ## Get a correlation ID from the server to use for a return message.
    try:
        recv_obj: Any = child_pipe.recv()
    except EOFError:
        ## Parent closed connection, terminate
        return
    assert isinstance(recv_obj, int)
    correlation_id: int = recv_obj

    ## Get a SandboxState object from the server.
    try:
        recv_obj = child_pipe.recv()
    except EOFError:
        return
    assert isinstance(recv_obj, SmdSandboxState)
    sandbox_state: SmdSandboxState = recv_obj

    user_id: str = str(sandbox_state.user_id_numeric)
    user_sandbox_repo: Path = Path(SmdCommon.sandbox_dir, user_id)
    if not user_sandbox_repo.is_dir():
        child_pipe.send(SmdCommServerDeleteFailedMsg(correlation_id))
        return

    user_sandbox_dir: Path = Path(user_sandbox_repo, sandbox_state.uuid_str)
    if not user_sandbox_dir.is_dir():
        child_pipe.send(SmdCommServerDeleteFailedMsg(correlation_id))
        return

    try:
        shutil.rmtree(user_sandbox_dir)
    except Exception:
        child_pipe.send(SmdCommServerDeleteFailedMsg(correlation_id))
        return

    child_pipe.send(SmdCommServerDeleteSuccessMsg(correlation_id))
