#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, duplicate-code

"""
clone_handler.py - Clone sandboxes.
"""

import os
import shutil
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from .common import (
    SmdCommon,
    SmdSandboxState,
    SmdEnsureDirResult,
    SmdEnsureDirStatus,
)

from .protocol import (
    SmdCommServerCloneSuccessMsg,
    SmdCommServerCloneFailedMsg,
)


# pylint: disable=too-many-return-statements
def clone_handler_main(child_pipe: Connection) -> None:
    """
    Entry point for clone_handler.py.
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
    cloned_sandbox_state: SmdSandboxState = recv_obj

    ## Get the UUID of the cloned sandbox.
    try:
        recv_obj = child_pipe.recv()
    except EOFError:
        return
    assert isinstance(recv_obj, str)
    source_sandbox_uuid_str: str = recv_obj

    user_id: str = str(cloned_sandbox_state.user_id_numeric)
    user_sandbox_repo: Path = Path(SmdCommon.sandbox_dir, user_id)
    if not user_sandbox_repo.is_dir():
        child_pipe.send(SmdCommServerCloneFailedMsg(correlation_id))
        return

    source_sandbox_dir: Path = Path(user_sandbox_repo, source_sandbox_uuid_str)
    if not source_sandbox_dir.is_dir():
        child_pipe.send(SmdCommServerCloneFailedMsg(correlation_id))
        return

    cloned_sandbox_dir: Path = Path(
        user_sandbox_repo, cloned_sandbox_state.uuid_str
    )
    ensure_dir_result: SmdEnsureDirResult = SmdCommon.ensure_dir(
        cloned_sandbox_dir, exists_ok=False
    )
    match ensure_dir_result:
        case SmdEnsureDirStatus.SUCCESS:
            pass
        case _:
            child_pipe.send(SmdCommServerCloneFailedMsg(correlation_id))
            return

    try:
        SmdCommon.write_sandbox_config(
            Path(cloned_sandbox_dir, SmdCommon.sandbox_config_file),
            cloned_sandbox_state,
        )
        shutil.copy(
            Path(source_sandbox_dir, SmdCommon.sandbox_root_file),
            Path(cloned_sandbox_dir, SmdCommon.sandbox_root_file),
        )
        shutil.copy(
            Path(source_sandbox_dir, SmdCommon.sandbox_data_file),
            Path(cloned_sandbox_dir, SmdCommon.sandbox_data_file),
        )
    except Exception:
        try:
            shutil.rmtree(cloned_sandbox_dir)
        except Exception:
            pass

        child_pipe.send(SmdCommServerCloneFailedMsg(correlation_id))
        return

    child_pipe.send(SmdCommServerCloneSuccessMsg(correlation_id))
