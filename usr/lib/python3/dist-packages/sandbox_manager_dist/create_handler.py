#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, duplicate-code

"""
create_handler.py - Creates sandboxes.
"""

import os
import shutil
import subprocess
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
    SmdCommServerCreateSuccessMsg,
    SmdCommServerCreateFailedMsg,
)


def bootstrap_sandbox_disk_images(
    user_sandbox_dir: Path, sandbox_state: SmdSandboxState
) -> None:
    """
    Creates the sandbox disk images, formats the data image, and installs
    Kicksecure CLI to the root image.
    """

    subprocess.run(
        [
            "/usr/libexec/sandbox-manager-dist/create-sandbox",
            user_sandbox_dir,
            SmdCommon.sandbox_root_file,
            SmdCommon.sandbox_data_file,
            str(sandbox_state.root_vol_size),
            str(sandbox_state.data_vol_size),
            str(SmdCommon.min_root_vol_size),
            str(SmdCommon.min_data_vol_size),
        ],
        check=True,
    )


def create_handler_main(child_pipe: Connection) -> None:
    """
    Entry point for create_handler.py.
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
    ensure_dir_result: SmdEnsureDirResult = SmdCommon.ensure_dir(
        user_sandbox_repo
    )
    match ensure_dir_result.status:
        case SmdEnsureDirStatus.SUCCESS:
            pass
        case _:
            child_pipe.send(SmdCommServerCreateFailedMsg(correlation_id))
            return

    user_sandbox_dir: Path = Path(user_sandbox_repo, sandbox_state.uuid_str)
    ensure_dir_result = SmdCommon.ensure_dir(user_sandbox_dir, exists_ok=False)
    match ensure_dir_result:
        case SmdEnsureDirStatus.SUCCESS:
            pass
        case _:
            child_pipe.send(SmdCommServerCreateFailedMsg(correlation_id))
            return

    try:
        SmdCommon.write_sandbox_config(
            Path(user_sandbox_dir, SmdCommon.sandbox_config_file),
            sandbox_state,
        )
        bootstrap_sandbox_disk_images(user_sandbox_dir, sandbox_state)
    except Exception:
        ## Try to delete the sandbox directory. Ignore failure, since all
        ## we're going to do is tell the client that sandbox creation failed,
        ## and it may be legitimately impossible to remove the sandbox dir
        ## (for instance, if the host filesystem went into read-only mode).
        try:
            shutil.rmtree(user_sandbox_dir)
        except Exception:
            pass

        child_pipe.send(SmdCommServerCreateFailedMsg(correlation_id))
        return

    child_pipe.send(SmdCommServerCreateSuccessMsg(correlation_id))
