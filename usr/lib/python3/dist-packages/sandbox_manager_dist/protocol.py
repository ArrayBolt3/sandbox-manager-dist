#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=too-many-lines, broad-exception-caught

"""
protocol.py - Defines the IPC protocol used for communication between the
frontend, backend, and agent, and provides tools for using that protocol
easily.
"""

import os
import socket
import stat
import pwd
from pathlib import Path
from typing import ClassVar
from .common import (
    SmdValidateType,
    SmdSocketType,
    SmdCommon,
)

msg_inc_int: int = 0
max_vol_size: int = (16 * 1024 * 1024 * 1024 * 1024) - 4096
max_mem_size: int = 1024 * 1024 * 1024 * 1024

######################
# CORE MESSAGE LOGIC #
######################


class SmdBaseMsg:
    """
    Base class for all message classes. Also stores a lookup list for all
    subclasses.
    """

    registry: list[type["SmdBaseMsg"]] = []
    name: ClassVar[str]
    msg_code: ClassVar[int]
    arg_count: ClassVar[int]
    trailing_binary: ClassVar[bool]

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        Base init function.
        """

        self.correlation_id: int = correlation_id
        self.arg_list: list[str] = arg_list if arg_list is not None else []
        self.binary_blob: bytes = (
            binary_blob if binary_blob is not None else b""
        )
        self.validate_msg_params()

    def __init_subclass__(
        cls,
        *,
        name: str | None = None,
        arg_count: int | None = None,
        trailing_binary: bool | None = None,
        register: bool = True,
    ) -> None:
        """
        Class derivation function.
        """

        if name is not None:
            cls.name = name
        if arg_count is not None:
            cls.arg_count = arg_count
        if trailing_binary is not None:
            cls.trailing_binary = trailing_binary
        if register:
            cls.msg_code = len(SmdBaseMsg.registry)
            SmdBaseMsg.registry.append(cls)

    def serialize(self) -> bytes:
        """
        Converts the message into a format that can be sent over the wire.
        """

        binary_arg_list: list[bytes] = [
            x.encode("utf-8") for x in self.arg_list
        ]

        ## message code: 2 bytes
        ## correlation ID: 16 bytes
        ## arguments: argument length + trailing NULL for each arg
        ## binary blob: blob length
        ## The length of the prefix itself doesn't count
        msg_len: int = (
            18
            + sum(len(x) + 1 for x in binary_arg_list)
            + len(self.binary_blob)
        )

        out_bytes: bytes = (
            msg_len.to_bytes(
                length=4,
                byteorder="big",
                signed=False,
            )
            + self.msg_code.to_bytes(
                length=2,
                byteorder="big",
                signed=False,
            )
            + self.correlation_id.to_bytes(
                length=16,
                byteorder="big",
                signed=False,
            )
            + b"".join([x + b"\0" for x in binary_arg_list])
            + self.binary_blob
        )

        ## Add 4 for the length of the prefix
        assert len(out_bytes) == msg_len + 4

        return out_bytes

    def validate_msg_params(self) -> None:
        """
        Shared validation logic to make sure the right parameters are passed
        when constructing a message object. Raises a ValueError if validation
        fails.
        """

        if not 0 <= self.correlation_id <= ((2**128) - 1):
            raise ValueError(
                "Correlation ID out of range for a 128-bit unsigned integer"
            )

        if len(self.arg_list) != self.arg_count:
            raise ValueError(f"Incorrect number of arguments for {self.name}")

        if self.binary_blob and not self.trailing_binary:
            raise ValueError(
                f"Binary blob provided to {self.name} but was not expected"
            )


class SmdControlClientMsg(SmdBaseMsg, register=False):
    """
    No-op class that groups together client-to-server control messages.
    """


class SmdControlServerMsg(SmdBaseMsg, register=False):
    """
    No-op class that groups together server-to-client control messages.
    """


class SmdCommClientMsg(SmdBaseMsg, register=False):
    """
    No-op class that groups together client-to-server comm messages.
    """


class SmdCommServerMsg(SmdBaseMsg, register=False):
    """
    Mostly-no-op class that groups together server-to-client comm messages.
    The only meaningful thing this does is add a flag for determining if a
    message is meant to be broadcast to multiple clients or not.
    """

    do_broadcast: ClassVar[bool]

    # pylint: disable=too-many-arguments
    def __init_subclass__(
        cls,
        *,
        name: str | None = None,
        arg_count: int | None = None,
        trailing_binary: bool | None = None,
        register: bool = True,
        do_broadcast: bool = False,
    ):
        super().__init_subclass__(
            name=name,
            arg_count=arg_count,
            trailing_binary=trailing_binary,
            register=register,
        )
        cls.do_broadcast = do_broadcast


## This class does not include a broadcast flag, because it is always
## broadcast when sent from server to client.
class SmdCommBidiMsg(SmdBaseMsg, register=False):
    """
    No-op class that groups together messages that may be sent from server to
    client or from client to server.
    """


###########################
# CONTROL CLIENT MESSAGES #
###########################


class SmdControlClientRegisterMsg(
    SmdControlClientMsg,
    name="REGISTER",
    arg_count=1,
    trailing_binary=False,
):
    """
    Requests creation of a comm socket for a specified user.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        REGISTER init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "User ID failed validation",
        )


class SmdControlClientUnregisterMsg(
    SmdControlClientMsg,
    name="UNREGISTER",
    arg_count=1,
    trailing_binary=False,
):
    """
    Requests removal of a comm socket for a specified user.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        UNREGISTER init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "User ID failed validation",
        )


###########################
# CONTROL SERVER MESSAGES #
###########################


class SmdControlServerRegisterSuccessMsg(
    SmdControlServerMsg,
    name="REGISTER_SUCCESS",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the client that comm socket creation has succeeded.
    """


class SmdControlServerRegisterExistsMsg(
    SmdControlServerMsg,
    name="REGISTER_EXISTS",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the client that the comm socket already exists.
    """


class SmdControlServerRegisterFailureMsg(
    SmdControlServerMsg,
    name="REGISTER_FAILURE",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the client that the comm socket could not be created.
    """


class SmdControlServerUnregisterSuccessMsg(
    SmdControlServerMsg,
    name="UNREGISTER_SUCCESS",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the client that comm socket removal has succeeded.
    """


class SmdControlServerUnregisterAbsentMsg(
    SmdControlServerMsg,
    name="UNREGISTER_ABSENT",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the client that the comm socket does not exist.
    """


class SmdControlServerUnregisterFailureMsg(
    SmdControlServerMsg,
    name="UNREGISTER_FAILURE",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the client that the comm socket could not be removed.
    """


########################
# COMM CLIENT MESSAGES #
########################


class SmdCommClientSyncMsg(
    SmdCommClientMsg,
    name="SYNC",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the server that the client is long-lived.
    """


class SmdCommClientQueryNeedRestartMsg(
    SmdCommClientMsg,
    name="QUERY_NEED_RESTART",
    arg_count=0,
    trailing_binary=False,
):
    """
    Asks the server if it needs to be restarted to apply software updates.
    """


class SmdCommClientRestartMsg(
    SmdCommClientMsg,
    name="RESTART",
    arg_count=0,
    trailing_binary=False,
):
    """
    Asks the server to restart itself.
    """


class SmdCommClientCreateStartMsg(
    SmdCommClientMsg,
    name="CREATE_START",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the server that messages defining a new sandbox are about to be
    sent.
    """


class SmdCommClientCreateEndMsg(
    SmdCommClientMsg,
    name="CREATE_END",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the server that messages defining a new sandbox have been set and
    asks the backend to create the sandbox.
    """


class SmdCommClientConfigStartMsg(
    SmdCommClientMsg,
    name="CONFIG_START",
    arg_count=1,
    trailing_binary=False,
):
    """
    Informs the server that messages modifying the configuration of a sandbox
    are about to be sent.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CONFIG_START init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )


class SmdCommClientConfigEndMsg(
    SmdCommClientMsg,
    name="CONFIG_END",
    arg_count=1,
    trailing_binary=False,
):
    """
    Informs the server that messages modifying the configuration of a sandbox
    have been sent and asks the backend to reconfigure the sandbox.
    """


class SmdCommClientGetConfigMsg(
    SmdCommClientMsg,
    name="GET_CONFIG",
    arg_count=1,
    trailing_binary=False,
):
    """
    Asks the server to send the configuration details of the specified
    sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        GET_CONFIG init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )


class SmdCommClientDeleteMsg(
    SmdCommClientMsg,
    name="DELETE",
    arg_count=1,
    trailing_binary=False,
):
    """
    Tells the server to delete a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        DELETE init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )


class SmdCommClientCloneMsg(
    SmdCommClientMsg,
    name="CLONE",
    arg_count=2,
    trailing_binary=False,
):
    """
    Tells the server to clone a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CLONE init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Existing sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.SANDBOX_NAME],
            "New sandbox name failed validation",
        )


class SmdCommClientBootMsg(
    SmdCommClientMsg,
    name="BOOT",
    arg_count=2,
    trailing_binary=False,
):
    """
    Tells the server to boot a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        BOOT init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.BOOT_MODE],
            "Boot mode failed validation",
        )


class SmdCommClientShutdownMsg(
    SmdCommClientMsg,
    name="SHUTDOWN",
    arg_count=2,
    trailing_binary=False,
):
    """
    Tells the server to shut down a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        SHUTDOWN init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.SHUTDOWN_MODE],
            "Shutdown mode failed validation",
        )


class SmdCommClientCreateFileBeginMsg(
    SmdCommClientMsg,
    name="CREATE_FILE_BEGIN",
    arg_count=5,
    trailing_binary=False,
):
    """
    Tells the backend to create a file in a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CREATE_FILE_BEGIN init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "Owning user failed validation",
        )
        SmdCommon.validate_id(
            arg_list[2],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "Owning group failed validation",
        )
        SmdCommon.validate_id(
            arg_list[3],
            [SmdValidateType.FILE_PERM],
            "File permissions failed validation",
        )
        SmdCommon.validate_id(
            arg_list[4],
            [SmdValidateType.ABSOLUTE_PATH],
            "File path failed validation",
        )


class SmdCommClientCreateFileBlockMsg(
    SmdCommClientMsg,
    name="CREATE_FILE_BLOCK",
    arg_count=0,
    trailing_binary=True,
):
    """
    Sends a block of a file being created to the server.
    """


class SmdCommClientCreateFileEndMsg(
    SmdCommClientMsg,
    name="CREATE_FILE_END",
    arg_count=0,
    trailing_binary=False,
):
    """
    Tells the server that all blocks of a file being created have been sent.
    """


class SmdCommClientCreateDirMsg(
    SmdCommClientMsg,
    name="CREATE_DIR",
    arg_count=5,
    trailing_binary=False,
):
    """
    Tells the backend to create a directory in a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CREATE_DIR init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "Owning user failed validation",
        )
        SmdCommon.validate_id(
            arg_list[2],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "Owning group failed validation",
        )
        SmdCommon.validate_id(
            arg_list[3],
            [SmdValidateType.FILE_PERM],
            "Directory permissions failed validation",
        )
        SmdCommon.validate_id(
            arg_list[4],
            [SmdValidateType.ABSOLUTE_PATH],
            "Directory path failed validation",
        )


class SmdCommClientListDirMsg(
    SmdCommClientMsg,
    name="LIST_DIR",
    arg_count=2,
    trailing_binary=False,
):
    """
    Tells the backend to send a directory listing to the client.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        LIST_DIR init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.ABSOLUTE_PATH],
            "Directory path failed validation",
        )


class SmdCommClientReadFileMsg(
    SmdCommClientMsg,
    name="READ_FILE",
    arg_count=2,
    trailing_binary=False,
):
    """
    Tells the backend to send a file to the client.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        READ_FILE init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.ABSOLUTE_PATH],
            "File path failed validation",
        )


class SmdCommClientReadFileAbortMsg(
    SmdCommClientMsg,
    name="READ_FILE_ABORT",
    arg_count=0,
    trailing_binary=False,
):
    """
    Tells the server to stop sending a file to the client.
    """


class SmdCommClientListAppsMsg(
    SmdCommClientMsg,
    name="LIST_APPS",
    arg_count=1,
    trailing_binary=False,
):
    """
    Tells the server to send a sandbox's app list.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        LIST_APPS init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )


class SmdCommClientGetAppInfoMsg(
    SmdCommClientMsg,
    name="GET_APP_INFO",
    arg_count=2,
    trailing_binary=False,
):
    """
    Tells the server to send application info (metadata) to the client.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        GET_APP_INFO init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.DESKTOP_FILE],
            "Desktop file name failed validation",
        )


class SmdCommClientExecMsg(
    SmdCommClientMsg,
    name="EXEC",
    arg_count=2,
    trailing_binary=True,
):
    """
    Tells the server to execute a program in a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        EXEC init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.DESKTOP_FILE],
            "Desktop file name failed validation",
        )


class SmdCommClientShellMsg(
    SmdCommClientMsg,
    name="SHELL",
    arg_count=1,
    trailing_binary=False,
):
    """
    Attempts to shell into a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        SHELL init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )


class SmdCommClientShellDisconnectMsg(
    SmdCommClientMsg,
    name="SHELL_DISCONNECT",
    arg_count=0,
    trailing_binary=False,
):
    """
    Informs the server that the client is disconnecting from the sandbox's
    console.
    """


class SmdCommClientShellHsBlockMsg(
    SmdCommClientMsg,
    name="SHELL_HS_BLOCK",
    arg_count=0,
    trailing_binary=True,
):
    """
    Sends a block of data to a sandbox's shell.
    """


########################
# COMM SERVER MESSAGES #
########################


class SmdCommServerConfirmNeedRestartMsg(
    SmdCommServerMsg,
    name="CONFIRM_NEED_RESTART",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that the server needs restarted to apply software
    updates.
    """


class SmdCommServerDenyNeedRestartMsg(
    SmdCommServerMsg,
    name="DENY_NEED_RESTART",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that the server does not need restarted.
    """


class SmdCommServerRestartInprogressMsg(
    SmdCommServerMsg,
    name="RESTART_INPROGRESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that the server is restarting.
    """


class SmdCommServerRestartDeniedMsg(
    SmdCommServerMsg,
    name="RESTART_DENIED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that the restart request was denied.
    """


class SmdCommServerDupNameMsg(
    SmdCommServerMsg,
    name="DUP_NAME",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a requested new sandbox name is already in use.
    """


class SmdCommServerSandboxRunningMsg(
    SmdCommServerMsg,
    name="SANDBOX_RUNNING",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a requested operation could not be performed
    because the target sandbox is running.
    """


class SmdCommServerSandboxNotRunningMsg(
    SmdCommServerMsg,
    name="SANDBOX_NOT_RUNNING",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a requested operation could not be performed
    because the target sandbox is not running.
    """


class SmdCommServerSandboxMissingMsg(
    SmdCommServerMsg,
    name="SANDBOX_MISSING",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a referenced sandbox cannot be found.
    """


class SmdCommServerConfigInvalidMsg(
    SmdCommServerMsg,
    name="CONFIG_INVALID",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that the configuration it attempted to apply to a
    sandbox is invalid.
    """


class SmdCommServerFsoMissingMsg(
    SmdCommServerMsg,
    name="FSO_MISSING",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a referenced filesystem object in a sandbox does
    not exist.
    """


class SmdCommServerFsoExistsMsg(
    SmdCommServerMsg,
    name="FSO_EXISTS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a referenced filesystem object in a sandbox
    already exists.
    """


class SmdCommServerCreateInprogressMsg(
    SmdCommServerMsg,
    name="CREATE_INPROGRESS",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox is being created.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CREATE_INPROGRESS init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )


class SmdCommServerCreateSuccessMsg(
    SmdCommServerMsg,
    name="CREATE_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox has been created.
    """


class SmdCommServerCreateFailedMsg(
    SmdCommServerMsg,
    name="CREATE_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that creation of a sandbox failed.
    """


class SmdCommServerConfigInprogressMsg(
    SmdCommServerMsg,
    name="CONFIG_INPROGRESS",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox is being configured.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CONFIG_INPROGRESS init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )


class SmdCommServerConfigSuccessMsg(
    SmdCommServerMsg,
    name="CONFIG_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox has been configured.
    """


class SmdCommServerConfigFailedMsg(
    SmdCommServerMsg,
    name="CONFIG_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that configuration of a sandbox failed.
    """


class SmdCommServerConfigInfoStartMsg(
    SmdCommServerMsg,
    name="CONFIG_INFO_START",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that messages defining a sandbox's configuration are
    about to be sent.
    """


class SmdCommServerConfigInfoEndMsg(
    SmdCommServerMsg,
    name="CONFIG_INFO_END",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that the server is done sending messages defining a
    sandbox's configuration.
    """


class SmdCommServerDeleteInprogressMsg(
    SmdCommServerMsg,
    name="DELETE_INPROGRESS",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox is being deleted.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        DELETE_INPROGRESS init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )


class SmdCommServerDeleteSuccessMsg(
    SmdCommServerMsg,
    name="DELETE_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox has been deleted.
    """


class SmdCommServerDeleteFailedMsg(
    SmdCommServerMsg,
    name="DELETE_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that deletion of a sandbox failed.
    """


class SmdCommServerCloneInprogressMsg(
    SmdCommServerMsg,
    name="CLONE_INPROGRESS",
    arg_count=3,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox is being cloned.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CLONE_INPROGRESS init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Original sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.UUID],
            "Cloned sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[2],
            [SmdValidateType.SANDBOX_NAME],
            "Cloned sandbox name failed validation",
        )


class SmdCommServerCloneSuccessMsg(
    SmdCommServerMsg,
    name="CLONE_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox has been cloned.
    """


class SmdCommServerCloneFailedMsg(
    SmdCommServerMsg,
    name="CLONE_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that cloning a sandbox failed.
    """


class SmdCommServerBootInprogressMsg(
    SmdCommServerMsg,
    name="BOOT_INPROGRESS",
    arg_count=2,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox is booting.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        BOOT_INPROGRESS init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.BOOT_MODE],
            "Boot mode failed validation",
        )


class SmdCommServerBootSuccessMsg(
    SmdCommServerMsg,
    name="BOOT_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox has been booted.
    """


class SmdCommServerBootFailedMsg(
    SmdCommServerMsg,
    name="BOOT_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that booting a sandbox failed.
    """


class SmdCommServerShutdownInprogressMsg(
    SmdCommServerMsg,
    name="SHUTDOWN_INPROGRESS",
    arg_count=2,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox is being shut down.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        SHUTDOWN_INPROGRESS init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.UUID],
            "Sandbox UUID failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.SHUTDOWN_MODE],
            "Shutdown mode failed validation",
        )


class SmdCommServerShutdownSuccessMsg(
    SmdCommServerMsg,
    name="SHUTDOWN_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that a sandbox has been shut down.
    """


class SmdCommServerShutdownFailedMsg(
    SmdCommServerMsg,
    name="SHUTDOWN_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=True,
):
    """
    Informs the client that shutting down a sandbox failed.
    """


class SmdCommServerCreateFileAckMsg(
    SmdCommServerMsg,
    name="CREATE_FILE_ACK",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a file creation request has been accepted and the
    server is ready to receive file data.
    """


class SmdCommServerCreateFileSuccessMsg(
    SmdCommServerMsg,
    name="CREATE_FILE_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a file has been created in a sandbox.
    """


class SmdCommServerCreateFileFailedMsg(
    SmdCommServerMsg,
    name="CREATE_FILE_FAILED",
    arg_count=0,
    trailing_binary=True,
    do_broadcast=False,
):
    """
    Informs the client that a file creation operation failed.
    """


class SmdCommServerCreateDirSuccessMsg(
    SmdCommServerMsg,
    name="CREATE_DIR_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a directory has been created in a sandbox.
    """


class SmdCommServerCreateDirFailedMsg(
    SmdCommServerMsg,
    name="CREATE_DIR_FAILED",
    arg_count=0,
    trailing_binary=True,
    do_broadcast=False,
):
    """
    Informs the client that a directory creation operation failed.
    """


class SmdCommServerListDirStartMsg(
    SmdCommServerMsg,
    name="LIST_DIR_START",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that messages defining a directory's metadata and its
    directory listing are about to be sent.
    """


class SmdCommServerListDirEntry(
    SmdCommServerMsg,
    name="LIST_DIR_ENTRY",
    arg_count=5,
    trailing_binary=True,
    do_broadcast=False,
):
    """
    Provides file or directory metadata to the client as part of a directory
    listing.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        LIST_DIR_ENTRY init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.FILE_TYPE],
            "File type failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "Owning user failed validation",
        )
        SmdCommon.validate_id(
            arg_list[2],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "Owning group failed validation",
        )
        SmdCommon.validate_id(
            arg_list[3],
            [SmdValidateType.FILE_PERM],
            "File/dir permissions failed validation",
        )
        SmdCommon.validate_id(
            arg_list[4],
            [SmdValidateType.FILE_NAME],
            "File/dir name failed validatoin",
        )


class SmdCommServerListDirEndMsg(
    SmdCommServerMsg,
    name="LIST_DIR_END",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that messages defining a directory's metadata and its
    directory listing are done being sent.
    """


class SmdCommServerListDirFailedMsg(
    SmdCommServerMsg,
    name="LIST_DIR_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that listing a directory failed.
    """


class SmdCommServerReadFileStartMsg(
    SmdCommServerMsg,
    name="READ_FILE_START",
    arg_count=3,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the frontend that the server is about to send it the contents of
    a file, and provides the file's metadata to the client.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        READ_FILE_START init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "Owning user failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.USER_NAME, SmdValidateType.USER_UID],
            "Owning group failed validation",
        )
        SmdCommon.validate_id(
            arg_list[2],
            [SmdValidateType.FILE_PERM],
            "File/dir permissions failed validation",
        )


class SmdCommServerReadFileBlockMsg(
    SmdCommServerMsg,
    name="READ_FILE_BLOCK",
    arg_count=0,
    trailing_binary=True,
    do_broadcast=False,
):
    """
    Provides a block of a file to the client.
    """


class SmdCommServerReadFileEndMsg(
    SmdCommServerMsg,
    name="READ_FILE_END",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a file has been fully sent.
    """


class SmdCommServerReadFileAbortAckMsg(
    SmdCommServerMsg,
    name="READ_FILE_ABORT_ACK",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a `READ_FILE_ABORT` message has been accepted and
    no further blocks of a file will be sent.
    """


class SmdCommServerReadFileFailedMsg(
    SmdCommServerMsg,
    name="READ_FILE_FAILED",
    arg_count=0,
    trailing_binary=True,
    do_broadcast=False,
):
    """
    Informs the client that the file read operation failed.
    """


class SmdCommServerListAppsStartMsg(
    SmdCommServerMsg,
    name="LIST_APPS_START",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that the server is about to send an application list.
    """


class SmdCommServerListAppsEntryMsg(
    SmdCommServerMsg,
    name="LIST_APPS_ENTRY",
    arg_count=3,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Provides an application entry to the client.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        LIST_APPS_ENTRY init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        ## There is intentionally no validation on the first two arguments
        ## (the application category and application name, respectively).
        SmdCommon.validate_id(
            arg_list[2],
            [SmdValidateType.DESKTOP_FILE],
            "Desktop file name failed validation",
        )


class SmdCommServerListAppsEndMsg(
    SmdCommServerMsg,
    name="LIST_APPS_END",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that the server is done sending an application list.
    """


class SmdCommServerListAppsFailedMsg(
    SmdCommServerMsg,
    name="LIST_APPS_FAILED",
    arg_count=0,
    trailing_binary=True,
    do_broadcast=False,
):
    """
    Informs the client that the app listing operation failed.
    """


class SmdCommServerGetAppInfoStartMsg(
    SmdCommServerMsg,
    name="GET_APP_INFO_START",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that messages defining an application's info are about
    to be sent.
    """


class SmdCommServerAppInfoNameMsg(
    SmdCommServerMsg,
    name="APP_INFO_NAME",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Provides an application's name to the client.
    """

    ## There is intentionally no argument validation for this message.


class SmdCommServerAppInfoGenericNameMsg(
    SmdCommServerMsg,
    name="APP_INFO_GENERIC_NAME",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Provides an application's generic name to the client.
    """

    ## There is intentionally no argument validation for this message.


class SmdCommServerAppInfoCommentMsg(
    SmdCommServerMsg,
    name="APP_INFO_COMMENT",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Provides an application's comment data to the client.
    """

    ## There is intentionally no argument validation for this message.


class SmdCommServerAppInfoExecMsg(
    SmdCommServerMsg,
    name="APP_INFO_EXEC",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Provides an application's execution data to the client.
    """

    ## There is intentionally no argument validation for this message. One
    ## might reasonably think this may require validation, but we execute
    ## desktop files entirely within the sandbox, so there is theoretically no
    ## risk to the host from not validating this.


class SmdCommServerAppInfoWorkDirMsg(
    SmdCommServerMsg,
    name="APP_INFO_WORK_DIR",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Provides an application's working directory to the client.
    """

    ## There is intentionally no argument validation for this message.


class SmdCommServerAppInfoMimetypeMsg(
    SmdCommServerMsg,
    name="APP_INFO_MIMETYPE",
    arg_count=1,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Provides a MIME type the application is capable of handling to the client.
    """

    ## There is intentionally no argument validation for this message.


class SmdCommServerGetAppInfoEndMsg(
    SmdCommServerMsg,
    name="GET_APP_INFO_END",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that messages defining an application's info have been
    sent.
    """


class SmdCommServerGetAppInfoFailedMsg(
    SmdCommServerMsg,
    name="GET_APP_INFO_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that getting an application's info failed.
    """


class SmdCommServerExecSuccessMsg(
    SmdCommServerMsg,
    name="EXEC_SUCCESS",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that an application has been successfully executed.
    """


class SmdCommServerExecFailedMsg(
    SmdCommServerMsg,
    name="EXEC_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that an application could not be executed.
    """


class SmdCommServerShellAckMsg(
    SmdCommServerMsg,
    name="SHELL_ACK",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a request to open the sandbox's console has been
    accepted.
    """


class SmdCommServerShellSbBlockMsg(
    SmdCommServerMsg,
    name="SHELL_SB_BLOCK",
    arg_count=0,
    trailing_binary=True,
    do_broadcast=False,
):
    """
    Sends a block of data from a sandbox's console.
    """


class SmdCommServerShellDisconnectedMsg(
    SmdCommServerMsg,
    name="SHELL_DISCONNECTED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that its connection to a sandbox's console has been
    disconnected.
    """


class SmdCommServerShellFailedMsg(
    SmdCommServerMsg,
    name="SHELL_FAILED",
    arg_count=0,
    trailing_binary=False,
    do_broadcast=False,
):
    """
    Informs the client that a sandbox's console cannot be connected to.
    """


#########################
# CONTROL BIDI MESSAGES #
#########################


class SmdCommBidiNameMsg(
    SmdCommBidiMsg,
    name="NAME",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies the name of a sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        NAME init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.SANDBOX_NAME],
            "Sandbox name failed validation",
        )


class SmdCommBidiDescriptionMsg(
    SmdCommServerMsg,
    name="DESCRIPTION",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies the description of a sandbox.
    """

    ## There is intentionally no argument validation for this message.


class SmdCommBidiRootVolSizeMsg(
    SmdCommBidiMsg,
    name="ROOT_VOL_SIZE",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies the size of a sandbox's root volume.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        ROOT_VOL_SIZE init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.DECIMAL_INT],
            "Root volume size failed validation",
        )
        vol_size: int = int(arg_list[0])
        if not 1 <= vol_size <= max_vol_size:
            raise ValueError("Root volume size out of range")


class SmdCommBidiDataVolSizeMsg(
    SmdCommBidiMsg,
    name="DATA_VOL_SIZE",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies the size of a sandbox's data volume.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        DATA_VOL_SIZE init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.DECIMAL_INT],
            "Data volume size failed validation",
        )
        vol_size: int = int(arg_list[0])
        if not 1 <= vol_size <= max_vol_size:
            raise ValueError("Data volume size out of range")


class SmdCommBidiMemoryMsg(
    SmdCommBidiMsg,
    name="MEMORY",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies the size of a sandbox's RAM.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        MEMORY init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.DECIMAL_INT],
            "Memory size failed validation",
        )
        mem_size: int = int(arg_list[0])
        if not 1 <= mem_size <= max_mem_size:
            raise ValueError("Memory size out of range")


class SmdCommBidiCpuWeightMsg(
    SmdCommBidiMsg,
    name="CPU_WEIGHT",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies a sandbox's CPU weight.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CPU_WEIGHT init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.DECIMAL_INT],
            "CPU weight failed validation",
        )
        cpu_weight: int = int(arg_list[0])
        if not 1 <= cpu_weight <= 10000:
            raise ValueError("CPU weight out of range")


class SmdCommBidiCpuCoresMdg(
    SmdCommBidiMsg,
    name="CPU_CORES",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies a sandbox's CPU core count. (Note that this is unused when using
    namespace-based sandboxing; it is intended for use with VM-based
    sandboxing in place of CPU_WEIGHT.)
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        CPU_CORES init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.DECIMAL_INT],
            "CPU weight failed validation",
        )
        cpu_cores: int = int(arg_list[0])
        if not 1 <= cpu_cores <= 256:
            raise ValueError("CPU cores out of range")


class SmdCommBidiIoWeightMsg(
    SmdCommBidiMsg,
    name="IO_WEIGHT",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies a sandbox's I/O weight.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        IO_WEIGHT init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.DECIMAL_INT],
            "IO weight failed validation",
        )
        cpu_weight: int = int(arg_list[0])
        if not 1 <= cpu_weight <= 10000:
            raise ValueError("IO weight out of range")


class SmdCommBidiAudioEnabledMsg(
    SmdCommBidiMsg,
    name="AUDIO_ENABLED",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies whether a sandbox has audio access.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        AUDIO_ENABLED init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.YN_BOOL],
            "Bool failed validation",
        )


class SmdCommBidiWaylandEnabledMsg(
    SmdCommBidiMsg,
    name="WAYLAND_ENABLED",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies whether a sandbox has Wayland access.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        WAYLAND_ENABLED init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.YN_BOOL],
            "Bool failed validation",
        )


class SmdCommBidiX11EnabledMsg(
    SmdCommBidiMsg,
    name="X11_ENABLED",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies whether a sandbox has X11 access.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        X11_ENABLED init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.YN_BOOL],
            "Bool failed validation",
        )


class SmdCommBidi3dEnabledMsg(
    SmdCommBidiMsg,
    name="3D_ENABLED",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies whether a sandbox has access to the GPU.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        3D_ENABLED init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.YN_BOOL],
            "Bool failed validation",
        )


class SmdCommBidiNetworkEnabledMsg(
    SmdCommBidiMsg,
    name="NETWORK_ENABLED",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies whether a sandbox has network access.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        NETWORK_ENABLED init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.YN_BOOL],
            "Bool failed validation",
        )


class SmdCommBidiNestedSandboxingEnabledMsg(
    SmdCommBidiMsg,
    name="NESTED_SANDBOXING_ENABLED",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies whether a sandbox is able to create additional user namespace
    sandboxes within itself.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        NESTED_SANDBOXING_ENABLED init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.YN_BOOL],
            "Bool failed validation",
        )


class SmdCommBidiSharedFsoMsg(
    SmdCommBidiMsg,
    name="SHARED_FSO",
    arg_count=3,
    trailing_binary=False,
):
    """
    Specifies a file or folder shared from the host to the sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        SHARED_FSO init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.WRITE_STATUS],
            "Write status failed validation",
        )
        SmdCommon.validate_id(
            arg_list[1],
            [SmdValidateType.ABSOLUTE_PATH],
            "Host path failed validation",
        )
        SmdCommon.validate_id(
            arg_list[2],
            [SmdValidateType.ABSOLUTE_PATH],
            "Sandbox path failed validation",
        )


class SmdCommBidiSharedDeviceMsg(
    SmdCommBidiMsg,
    name="SHARED_DEVICE",
    arg_count=1,
    trailing_binary=False,
):
    """
    Specifies a device shared from the host to the sandbox.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        SHARED_DEVICE init function.
        """

        super().__init__(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.ABSOLUTE_PATH],
            "Device path failed validation",
        )


class SmdSession:
    """
    A connection between the sandbox-manager-dist server and client.
    """

    def __init__(
        self,
        server_socket_fileno: int = -1,
        session_socket: socket.socket | None = None,
        user_name: str | None = None,
        is_control_session: bool = False,
    ) -> None:
        """
        Session init function.
        """

        ## Possible socket/user name/control session bool argument
        ## combinations:
        ## - session_socket set, user_name set, is_control_session = True:
        ##   - Illegal, user_name cannot be set when is_control_session is
        ##     True.
        ## - session_socket set, user_name set, is_control_session = False:
        ##   - Legal, server-side comm session, socket passed by
        ##     SmdServerSocket.get_session.
        ## - session_socket set, user_name not set, is_control_session = True:
        ##   - Legal, server-side control session, socket passed by
        ##     SmdServerSocket.get_session.
        ## - session_socket set, user_name not set, is_control_session = False:
        ##   - Illegal, user_name must be set when is_control_session is False.
        ## - session_socket not set, user_name set, is_control_session = True:
        ##   - Illegal, user_name cannot be set when is_control_session is True.
        ## - session_socket not set, user_name set, is_control_session = False:
        ##   - Legal, client-side comm session, socket created here.
        ## - session_socket not set, user_name not set, is_control_session
        ##   = True:
        ##   - Legal, client-side control session, socket created here.
        ## - session_socket not set, user_name not set, is_control_session
        ##   = False:
        ##   - Illegal, user_name must be set when is_control_session is False.
        ##
        ## server_socket_fileno must be set if session_socket is passed,
        ## otherwise it must be omitted.

        self.server_socket_fileno: int = server_socket_fileno
        self.user_name: str | None
        self.backend_socket: socket.socket
        self.is_control_session: bool = is_control_session
        self.is_server_side: bool = False
        self.is_session_open: bool = True

        if server_socket_fileno != -1 and session_socket is None:
            raise ValueError(
                "server_socket_fileno cannot be passed if session_socket is "
                + "not passed"
            )
        if server_socket_fileno == -1 and session_socket is not None:
            raise ValueError(
                "server_socket_fileno must be passed if session_socket is "
                + "passed"
            )

        if not is_control_session and user_name is None:
            raise ValueError(
                "user_name must be passed if creating a comm session"
            )
        if is_control_session and user_name is not None:
            raise ValueError(
                "user_name must not be passed when creating a control session"
            )

        if session_socket is None:
            ## Client-side
            self.backend_socket = socket.socket(family=socket.AF_UNIX)
            if is_control_session:
                socket_path: Path = SmdCommon.control_path
            else:
                assert user_name is not None
                orig_user_name: str = user_name
                user_name = SmdCommon.normalize_user_id(user_name)
                if user_name is None:
                    raise ValueError(
                        f"Account '{orig_user_name}' does not exist"
                    )
                socket_path = Path(SmdCommon.comm_dir, user_name)
                if not os.access(socket_path, os.R_OK | os.W_OK):
                    raise PermissionError(
                        f"Cannot access '{str(socket_path)}' for reading and "
                        "writing"
                    )
            self.backend_socket.connect(str(socket_path))
        else:
            ## Server-side
            self.is_server_side = True
            self.backend_socket = session_socket

        self.user_name = user_name

        ## We intentionally set a socket timeout even though the ocnnection
        ## between the client and server is expected to be long-lived. poll()
        ## can be used to determine if data is coming or not, but once the
        ## data is coming, it should be there immediately or at least soon.
        self.backend_socket.settimeout(0.1)

    def close_session(self) -> None:
        """
        Closes the session. No further messages can be sent by either side
        once this is called.
        """

        self.backend_socket.shutdown(socket.SHUT_RDWR)
        self.backend_socket.close()
        self.is_session_open = False

    def __abort_connection(self, msg: str, e: Exception | None = None) -> None:
        """
        Closes the connection and raises a ConnectionAbortedError with the
        specified message.
        """

        self.close_session()
        if e is None:
            raise ConnectionAbortedError(msg)
        raise ConnectionAbortedError(msg) from e

    # pylint: disable=too-many-branches
    def __recv_msg(self) -> bytes:
        """
        Receives a low-level message from the backend socket. You should use
        get_msg() if you want to get an actual message object back. On the
        client side, this will wait as long as necessary to get all data from
        the server. On the server side, this will give up on clients that send
        data too slowly.
        """

        server_max_loops: int = 5
        header_len: int = 4
        recv_buf: bytearray = bytearray()

        while len(recv_buf) != header_len:
            if self.is_server_side:
                if server_max_loops == 0:
                    self.__abort_connection("Connection is too slow")
                server_max_loops -= 1
            try:
                tmp_buf: bytes = self.backend_socket.recv(header_len)
            except socket.timeout as e:
                if self.is_server_side:
                    self.__abort_connection("Connection locked up", e)
                continue
            if tmp_buf == b"":
                self.__abort_connection("Connection unexpectedly closed")
            header_len -= len(tmp_buf)
            recv_buf.extend(tmp_buf)

        msg_len: int = int.from_bytes(recv_buf, byteorder="big")

        if self.is_server_side and msg_len > 16384:
            self.__abort_connection("Received message is too long")

        recv_buf = bytearray()

        while len(recv_buf) != msg_len:
            if self.is_server_side:
                if server_max_loops == 0:
                    self.__abort_connection("Connection is too slow")
                server_max_loops -= 1
            try:
                tmp_buf = self.backend_socket.recv(msg_len)
            except socket.timeout as e:
                if self.is_server_side:
                    self.__abort_connection("Connection locked up", e)
                continue
            if tmp_buf == b"":
                self.__abort_connection("Connection unexpectedly closed")
            msg_len -= len(tmp_buf)
            recv_buf.extend(tmp_buf)

        return bytes(recv_buf)

    def __send_msg(self, msg_obj: SmdBaseMsg) -> None:
        """
        Sends a message to the remote client or server. This does not validate
        that the message being sent is appropriate coming from the sender; you
        should use send_msg() instead.
        """

        msg_bytes: bytes = msg_obj.serialize()
        msg_len_bytes: bytes = len(msg_bytes).to_bytes(
            4, byteorder="big", signed=False
        )
        msg_payload: bytes = msg_len_bytes + msg_bytes
        msg_payload_len: int = len(msg_payload)
        msg_payload_sent: int = 0
        while msg_payload_sent < msg_payload_len:
            msg_sent: int = self.backend_socket.send(
                msg_payload[msg_payload_sent:]
            )
            if msg_sent == 0:
                self.__abort_connection("Connection unexpectedly closed")
            msg_payload_sent += msg_sent

    def __deserialize_msg(self, msg_bytes: bytes) -> SmdBaseMsg:
        """
        Converts a message in binary form into a message object.
        """

        ## message code = 2 bytes, correlation ID = 16 bytes, that's the
        ## entirety of messages that lack arguments and a binary blob.
        if len(msg_bytes) < 18:
            self.__abort_connection("Message too short for any message type!")

        msg_code: int = int.from_bytes(
            msg_bytes[:2], byteorder="big", signed=False
        )
        if msg_code >= len(SmdBaseMsg.registry):
            self.__abort_connection(f"Message code '{msg_code}' out of bounds!")

        correlation_id: int = int.from_bytes(
            msg_bytes[2:18], byteorder="big", signed=False
        )

        msg_type: type["SmdBaseMsg"] = SmdBaseMsg.registry[msg_code]
        arg_and_blob_list: list[bytes] = msg_bytes[18:].split(
            b"\0", maxsplit=msg_type.arg_count
        )
        actual_arg_count = len(arg_and_blob_list) - 1

        if actual_arg_count < msg_type.arg_count:
            self.__abort_connection(
                f"Insufficient arguments for message '{msg_type.name}', "
                + f"expected {msg_type.arg_count} arguments, got "
                + f"{actual_arg_count}"
            )
        if actual_arg_count > msg_type.arg_count:
            self.__abort_connection(
                f"Too many arguments for message '{msg_type.name}', "
                + f"expected {msg_type.arg_count} arguments, got "
                + f"{actual_arg_count}"
            )

        if msg_type.trailing_binary and arg_and_blob_list[-1] == b"":
            self.__abort_connection(
                f"Missing binary blob for message '{msg_type.name}'"
            )
        if not msg_type.trailing_binary and arg_and_blob_list[-1] != b"":
            self.__abort_connection(
                f"Unexpected binary blob for message '{msg_type.name}'"
            )

        try:
            msg_obj: SmdBaseMsg = msg_type(
                correlation_id,
                [x.decode("utf-8") for x in arg_and_blob_list[:-1]],
                arg_and_blob_list[-1],
            )
        except Exception as e:
            self.__abort_connection(
                f"Validation error while processing message '{msg_type.name}'",
                e,
            )
        return msg_obj

    def get_msg(self) -> SmdBaseMsg:
        """
        Gets a message from the remote client or server, deserializes it, and
        ensures it is appropriate for the receiver.
        """

        if not self.is_session_open:
            raise IOError("Session is closed")

        msg_bytes: bytes = self.__recv_msg()
        msg: SmdBaseMsg = self.__deserialize_msg(msg_bytes)

        ## We're on the receiving end, so servers expect to receive client
        ## messages, and clients expect to receive server messages.
        if self.is_control_session and self.is_server_side:
            if not isinstance(msg, SmdControlClientMsg):
                self.__abort_connection(
                    "Control server received an inappropriate message: "
                    + f"'{str(type(msg))}'"
                )
        if self.is_control_session and not self.is_server_side:
            if not isinstance(msg, SmdControlServerMsg):
                self.__abort_connection(
                    "Control client received an inappropriate message: "
                    + f"'{str(type(msg))}'"
                )
        if not self.is_control_session and self.is_server_side:
            if not isinstance(msg, SmdCommClientMsg) and not isinstance(
                msg, SmdCommBidiMsg
            ):
                self.__abort_connection(
                    "Comm server received an inappropriate message: "
                    + f"'{str(type(msg))}'"
                )
        if not self.is_control_session and not self.is_server_side:
            if not isinstance(msg, SmdCommServerMsg) and not isinstance(
                msg, SmdCommBidiMsg
            ):
                self.__abort_connection(
                    "Comm client received an inappropriate message: "
                    + f"'{str(type(msg))}'"
                )
        return msg

    def send_msg(self, msg: SmdBaseMsg) -> None:
        """
        Sends a message to the remote client or server. Validates that the
        message being sent is appropriate coming from the sender.
        """

        if not self.is_session_open:
            raise IOError("Session is closed")

        ## We're on the sending end, so servers expect to send server
        ## messages, and clients expect to send client messages.
        if self.is_control_session and not self.is_server_side:
            if not isinstance(msg, SmdControlClientMsg):
                self.__abort_connection(
                    "Control client tried to send an inappropriate message: "
                    + f"'{str(type(msg))}'"
                )
        if self.is_control_session and self.is_server_side:
            if not isinstance(msg, SmdControlServerMsg):
                self.__abort_connection(
                    "Control server tried to send an inappropriate message: "
                    + f"'{str(type(msg))}'"
                )
        if not self.is_control_session and not self.is_server_side:
            if not isinstance(msg, SmdCommClientMsg) and not isinstance(
                msg, SmdCommBidiMsg
            ):
                self.__abort_connection(
                    "Comm client tried to send an inappropriate message: "
                    + f"'{str(type(msg))}'"
                )
        if not self.is_control_session and self.is_server_side:
            if not isinstance(msg, SmdCommServerMsg) and not isinstance(
                msg, SmdCommBidiMsg
            ):
                self.__abort_connection(
                    "Comm server tried to send an inappropriate message: "
                    + f"'{str(type(msg))}'"
                )

        self.__send_msg(msg)


class SmdServerSocket:
    """
    A server-side listening socket for control and comm connections. Use this
    only on the server for listening for incoming connections. Both the server
    and client should use SmdSession objects for actual communication.
    """

    def __init__(
        self, socket_type: SmdSocketType, user_name: str | None = None
    ) -> None:
        """
        Server socket init function.
        """

        self.backend_socket: socket.socket
        self.socket_type: SmdSocketType
        self.socket_path: Path
        self.is_socket_connected: bool = True
        self.user_name: str | None = None

        if socket_type == SmdSocketType.CONTROL:
            if user_name is not None:
                raise ValueError(
                    "user_name is only valid with "
                    "SmdSocketType.COMMUNICATION"
                )
            self.backend_socket = socket.socket(family=socket.AF_UNIX)
            self.socket_path = SmdCommon.control_path
            self.backend_socket.bind(str(self.socket_path))
            os.chown(SmdCommon.control_path, 0, 0)
            os.chmod(SmdCommon.control_path, stat.S_IRUSR | stat.S_IWUSR)
            self.backend_socket.listen(10)
        else:
            if user_name is None:
                raise ValueError(
                    "user_name must be provided when using "
                    "SmdSocketType.COMMUNICATION"
                )

            orig_user_name: str = user_name
            user_name = SmdCommon.normalize_user_id(user_name)
            if user_name is None:
                raise ValueError(f"Account '{orig_user_name}' does not exist")

            try:
                user_info: pwd.struct_passwd = pwd.getpwnam(user_name)
                target_uid: int = user_info.pw_uid
                target_gid: int = user_info.pw_gid
            except Exception as e:
                raise ValueError(f"Account '{user_name}' does not exist") from e

            self.backend_socket = socket.socket(family=socket.AF_UNIX)
            self.socket_path = Path(SmdCommon.comm_dir, user_name)
            self.backend_socket.bind(str(self.socket_path))
            os.chown(self.socket_path, target_uid, target_gid)
            os.chmod(self.socket_path, stat.S_IRUSR | stat.S_IWUSR)
            self.backend_socket.listen(10)
            self.user_name = user_name

        self.socket_type = socket_type

    def get_session(self) -> SmdSession:
        """
        Gets a session from the listening socket. For those used to using
        sockets directly, this is an analogue to socket.accept().
        """

        ## socket.accept returns a (socket, address) tuple, we only need the
        ## socket from this
        session_socket: socket.socket = self.backend_socket.accept()[0]
        if self.socket_type == SmdSocketType.CONTROL:
            return SmdSession(
                server_socket_fileno=self.fileno(),
                session_socket=session_socket,
                is_control_session=True,
            )

        assert self.user_name is not None
        return SmdSession(
            server_socket_fileno=self.fileno(),
            session_socket=session_socket,
            user_name=self.user_name,
            is_control_session=False,
        )

    def fileno(self) -> int:
        """
        Gets the file descriptor number of the backend socket.
        """

        return self.backend_socket.fileno()

    def close(self) -> None:
        """
        Close the listening socket.
        """

        self.backend_socket.close()
        self.socket_path.unlink(missing_ok=True)
        self.is_socket_connected = False
