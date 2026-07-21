#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, duplicate-code

"""
config_handler.py - Reconfigure sandboxes.
"""

import os
from multiprocessing.connection import Connection
from pathlib import Path
import subprocess
from typing import Any

from .common import (
    SmdCommon,
    SmdSandboxState,
)

from .protocol import (
    SmdCommServerConfigSuccessMsg,
    SmdCommServerConfigFailedMsg,
)

def resize_sandbox_disk_images(
    user_sandbox_dir: Path, sandbox_state: SmdSandboxState
) -> None:
    """
    Checks the size of each of the sandbox's disk images, and resizes disk
    images that are not the size specified in the configuration.
    """

    root_vol_path: Path = Path(user_sandbox_dir, SmdCommon.sandbox_root_file)
    data_vol_path: Path = Path(user_sandbox_dir, SmdCommon.sandbox_data_file)
    root_vol_size: int = root_vol_path.stat().st_size
    data_vol_size: int = data_vol_path.stat().st_size

    for target_vol, vol_size, desired_vol_size in (
        (root_vol_path, root_vol_size, sandbox_state.root_vol_size),
        (data_vol_path, data_vol_size, sandbox_state.data_vol_size),
    ):
        if vol_size < desired_vol_size:  ## filesystem needs grown
            with open(target_vol, "r+b") as f:
                f.truncate(desired_vol_size)
            subprocess.run(
                ["/usr/sbin/resize2fs", "-f", "--", str(target_vol)],
                check=True,
            )
        elif vol_size > desired_vol_size: ## filesystem needs shrunk
            subprocess.run(
                [
                    "/usr/sbin/resize2fs",
                    "-f",
                    "--",
                    str(target_vol),
                    str(desired_vol_size / 4096),
                ],
                check=True,
            )
            with open(target_vol, "r+b") as f:
                f.truncate(desired_vol_size)

def config_handler_main(child_pipe: Connection) -> None:
    """
    Entry point for config_handler.py.
    """

    ## Set restrictive umask to ensure sandbox files are only accessible by
    ## root.
    os.umask(0o077)

    ## Get a correlation IS from the server to use for a return message.
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
        child_pipe.send(SmdCommServerConfigFailedMsg(correlation_id))
        return

    user_sandbox_dir: Path = Path(user_sandbox_repo, sandbox_state.uuid_str)
    if not user_sandbox_dir.is_dir():
        child_pipe.send(SmdCommServerConfigFailedMsg(correlation_id))
        return

    try:
        resize_sandbox_disk_images(user_sandbox_dir, sandbox_state)
        SmdCommon.write_sandbox_config(
            Path(user_sandbox_dir, SmdCommon.sandbox_config_file),
            sandbox_state,
        )
    except Exception:
        child_pipe.send(SmdCommServerConfigFailedMsg(correlation_id))
        return

    child_pipe.send(SmdCommServerConfigSuccessMsg(correlation_id))
