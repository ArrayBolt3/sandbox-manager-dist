#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=too-many-lines

"""
protocol.py - Defines protocol messages used for communication between the
frontend, backend, and agent.
"""

from typing import ClassVar, Final
from .common import (
    SmdValidateType,
    SmdCommon,
)

msg_inc_int: int = 0

def next_msg_code() -> int:
    """
    Generates a new message code. We use this instead of explicitly setting
    message codes to avoid accidentally assigning the same code to two messages.
    """

    # pylint: disable=global-statement
    global msg_inc_int
    msg_inc_int += 1
    return msg_inc_int

########################
# CORE MESSAGE CLASSES #
########################

class SmdBaseMsg:
    """
    Base class for all message classes.
    """

    name: ClassVar[str]
    msg_code: ClassVar[int]
    arg_count: ClassVar[int]
    trailing_binary: ClassVar[bool]

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None,
        binary_blob: bytes | None,
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
        msg_len: int = 18 + sum(
            len(x) + 1 for x in binary_arg_list
        ) + len(self.binary_blob)

        out_bytes: bytes = msg_len.to_bytes(
            length=4,
            byteorder="big",
            signed=False,
        ) + self.msg_code.to_bytes(
            length=2,
            byteorder="big",
            signed=False,
        ) + self.correlation_id.to_bytes(
            length=16,
            byteorder="big",
            signed=False,
        ) + b"".join([x + b"\0" for x in binary_arg_list]) + self.binary_blob

        ## Add 4 for the length of the prefix
        assert len(out_bytes) == msg_len + 4

        return out_bytes

    def validate_msg_params(self) -> None:
        """
        Shared validation logic to make sure the right parameters are passed
        when constructing a message object. Raises a ValueError if validation
        fails.
        """

        if not 0 <= self.correlation_id <= ((2 ** 128) - 1):
            raise ValueError(
                "Correlation ID out of range for a 128-bit unsigned integer"
            )

        if len(self.arg_list) != self.arg_count:
            raise ValueError(f"Incorrect number of arguments for {self.name}")

        if self.binary_blob and not self.trailing_binary:
            raise ValueError(
                f"Binary blob provided to {self.name} but was not expected"
            )

class SmdControlClientMsg(SmdBaseMsg):
    """
    No-op class that groups together client-to-server control messages.
    """

class SmdControlServerMsg(SmdBaseMsg):
    """
    No-op class that groups together server-to-client control messages.
    """

class SmdCommClientMsg(SmdBaseMsg):
    """
    No-op class that groups together client-to-server comm messages.
    """

class SmdCommServerMsg(SmdBaseMsg):
    """
    No-op class that groups together server-to-client comm messages.
    """

class SmdCommBidiMsg(SmdBaseMsg):
    """
    No-op class that groups together messages that may be sent from server to
    client or from client to server.
    """

###########################
# CONTROL CLIENT MESSAGES #
###########################

class SmdControlClientRegisterMsg(SmdControlClientMsg):
    """
    Requests creation of a comm socket for a specified user.
    """

    name: ClassVar[Final[str]] = "REGISTER"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdControlClientUnregisterMsg(SmdControlClientMsg):
    """
    Requests removal of a comm socket for a specified user.
    """

    name: ClassVar[Final[str]] = "UNREGISTER"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdControlServerRegisterSuccessMsg(SmdControlServerMsg):
    """
    Informs the client that comm socket creation has succeeded.
    """

    name: ClassVar[Final[str]] = "REGISTER_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdControlServerRegisterExistsMsg(SmdControlServerMsg):
    """
    Informs the client that the comm socket already exists.
    """

    name: ClassVar[Final[str]] = "REGISTER_EXISTS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdControlServerRegisterFailureMsg(SmdControlServerMsg):
    """
    Informs the client that the comm socket could not be created.
    """

    name: ClassVar[Final[str]] = "REGISTER_FAILURE"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdControlServerUnregisterSuccessMsg(SmdControlServerMsg):
    """
    Informs the client that comm socket removal has succeeded.
    """

    name: ClassVar[Final[str]] = "UNREGISTER_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdControlServerUnregisterAbsentMsg(SmdControlServerMsg):
    """
    Informs the client that the comm socket does not exist.
    """

    name: ClassVar[Final[str]] = "UNREGISTER_ABSENT"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdControlServerUnregisterFailureMsg(SmdControlServerMsg):
    """
    Informs the client that the comm socket could not be removed.
    """

    name: ClassVar[Final[str]] = "UNREGISTER_FAILURE"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

########################
# COMM CLIENT MESSAGES #
########################

class SmdCommClientSyncMsg(SmdCommClientMsg):
    """
    Informs the server that the client is long-lived.
    """

    name: ClassVar[Final[str]] = "SYNC"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommClientQueryNeedRestartMsg(SmdCommClientMsg):
    """
    Asks the server if it needs to be restarted to apply software updates.
    """

    name: ClassVar[Final[str]] = "QUERY_NEED_RESTART"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommClientRestartMsg(SmdCommClientMsg):
    """
    Asks the server to restart itself.
    """

    name: ClassVar[Final[str]] = "RESTART"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommClientCreateStartMsg(SmdCommClientMsg):
    """
    Informs the server that messages defining a new sandbox are about to be
    sent.
    """

    name: ClassVar[Final[str]] = "CREATE_START"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommClientCreateEndMsg(SmdCommClientMsg):
    """
    Informs the server that messages defining a new sandbox have been set and
    asks the backend to create the sandbox.
    """

    name: ClassVar[Final[str]] = "CREATE_END"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommClientConfigStartMsg(SmdCommClientMsg):
    """
    Informs the server that messages modifying the configuration of a sandbox
    are about to be sent.
    """

    name: ClassVar[Final[str]] = "CONFIG_START"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientConfigEndMsg(SmdCommClientMsg):
    """
    Informs the server that messages modifying the configuration of a sandbox
    have been sent and asks the backend to reconfigure the sandbox.
    """

    name: ClassVar[Final[str]] = "CONFIG_END"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommClientGetConfigMsg(SmdCommClientMsg):
    """
    Asks the server to send the configuration details of the specified
    sandbox.
    """

    name: ClassVar[Final[str]] = "GET_CONFIG"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientDeleteMsg(SmdCommClientMsg):
    """
    Tells the server to delete a sandbox.
    """

    name: ClassVar[Final[str]] = "DELETE"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientCloneMsg(SmdCommClientMsg):
    """
    Tells the server to clone a sandbox.
    """

    name: ClassVar[Final[str]] = "CLONE"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientBootMsg(SmdCommClientMsg):
    """
    Tells the server to boot a sandbox.
    """

    name: ClassVar[Final[str]] = "BOOT"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientShutdownMsg(SmdCommClientMsg):
    """
    Tells the server to shut down a sandbox.
    """

    name: ClassVar[Final[str]] = "SHUTDOWN"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientCreateFileBeginMsg(SmdCommClientMsg):
    """
    Tells the backend to create a file in a sandbox.
    """

    name: ClassVar[Final[str]] = "CREATE_FILE_BEGIN"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 5
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientCreateFileBlockMsg(SmdCommClientMsg):
    """
    Sends a block of a file being created to the server.
    """

    name: ClassVar[Final[str]] = "CREATE_FILE_BLOCK"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = True

class SmdCommClientCreateFileEndMsg(SmdCommClientMsg):
    """
    Tells the server that all blocks of a file being created have been sent.
    """

    name: ClassVar[Final[str]] = "CREATE_FILE_END"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommClientCreateDirMsg(SmdCommClientMsg):
    """
    Tells the backend to create a directory in a sandbox.
    """

    name: ClassVar[Final[str]] = "CREATE_DIR"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 5
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientListDirMsg(SmdCommClientMsg):
    """
    Tells the backend to send a directory listing to the client.
    """

    name: ClassVar[Final[str]] = "LIST_DIR"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientReadFileMsg(SmdCommClientMsg):
    """
    Tells the backend to send a file to the client.
    """

    name: ClassVar[Final[str]] = "READ_FILE"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientReadFileAbortMsg(SmdCommClientMsg):
    """
    Tells the server to stop sending a file to the client.
    """

    name: ClassVar[Final[str]] = "READ_FILE_ABORT"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommClientListAppsMsg(SmdCommClientMsg):
    """
    Tells the server to send a sandbox's app list.
    """

    name: ClassVar[Final[str]] = "LIST_APPS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientGetAppInfoMsg(SmdCommClientMsg):
    """
    Tells the server to send application info (metadata) to the client.
    """

    name: ClassVar[Final[str]] = "GET_APP_INFO"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientExecMsg(SmdCommClientMsg):
    """
    Tells the server to execute a program in a sandbox.
    """

    name: ClassVar[Final[str]] = "EXEC"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = True

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
            [SmdValidateType.RELATIVE_PATH],
            "Program path failed validation",
        )

class SmdCommClientShellMsg(SmdCommClientMsg):
    """
    Attempts to shell into a sandbox.
    """

    name: ClassVar[Final[str]] = "SHELL"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommClientShellHsBlockMsg(SmdCommClientMsg):
    """
    Sends a block of data to a sandbox's shell.
    """

    name: ClassVar[Final[str]] = "SHELL_HS_BLOCK"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = True

########################
# COMM SERVER MESSAGES #
########################

class SmdCommServerConfirmNeedRestartMsg(SmdCommServerMsg):
    """
    Informs the client that the server needs restarted to apply software
    updates.
    """

    name: ClassVar[Final[str]] = "CONFIRM_NEED_RESTART"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerDenyNeedRestartMsg(SmdCommServerMsg):
    """
    Informs the client that the server does not need restarted.
    """

    name: ClassVar[Final[str]] = "DENY_NEED_RESTART"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerRestartInprogressMsg(SmdCommServerMsg):
    """
    Informs the client that the server is restarting.
    """

    name: ClassVar[Final[str]] = "RESTART_INPROGRESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerRestartDeniedMsg(SmdCommServerMsg):
    """
    Informs the client that the restart request was denied.
    """

    name: ClassVar[Final[str]] = "RESTART_DENIED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerDupNameMsg(SmdCommServerMsg):
    """
    Informs the client that a requested new sandbox name is already in use.
    """

    name: ClassVar[Final[str]] = "DUP_NAME"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerSandboxRunningMsg(SmdCommServerMsg):
    """
    Informs the client that a requested operation could not be performed
    because the target sandbox is running.
    """

    name: ClassVar[Final[str]] = "SANDBOX_RUNNING"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerSandboxNotRunningMsg(SmdCommServerMsg):
    """
    Informs the client that a requested operation could not be performed
    because the target sandbox is not running.
    """

    name: ClassVar[Final[str]] = "SANDBOX_NOT_RUNNING"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerSandboxMissingMsg(SmdCommServerMsg):
    """
    Informs the client that a referenced sandbox cannot be found.
    """

    name: ClassVar[Final[str]] = "SANDBOX_MISSING"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerConfigInvalidMsg(SmdCommServerMsg):
    """
    Informs the client that the configuration it attempted to apply to a
    sandbox is invalid.
    """

    name: ClassVar[Final[str]] = "CONFIG_INVALID"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerFsoMissingMsg(SmdCommServerMsg):
    """
    Informs the client that a referenced filesystem object in a sandbox does
    not exist.
    """

    name: ClassVar[Final[str]] = "FSO_MISSING"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerFsoExistsMsg(SmdCommServerMsg):
    """
    Informs the client that a referenced filesystem object in a sandbox
    already exists.
    """

    name: ClassVar[Final[str]] = "FSO_EXISTS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerCreateInprogressMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox is being created.
    """

    name: ClassVar[Final[str]] = "CREATE_INPROGRESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommServerCreateSuccessMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox has been created.
    """

    name: ClassVar[Final[str]] = "CREATE_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerCreateFailedMsg(SmdCommServerMsg):
    """
    Informs the client that creation of a sandbox failed.
    """

    name: ClassVar[Final[str]] = "CREATE_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerConfigInprogressMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox is being configured.
    """

    name: ClassVar[Final[str]] = "CONFIG_INPROGRESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommServerConfigSuccessMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox has been configured.
    """

    name: ClassVar[Final[str]] = "CONFIG_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerConfigFailedMsg(SmdCommServerMsg):
    """
    Informs the client that configuration of a sandbox failed.
    """

    name: ClassVar[Final[str]] = "CONFIG_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerConfigInfoStartMsg(SmdCommServerMsg):
    """
    Informs the client that messages defining a sandbox's configuration are
    about to be sent.
    """

    name: ClassVar[Final[str]] = "CONFIG_INFO_START"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerConfigInfoEndMsg(SmdCommServerMsg):
    """
    Informs the client that the server is done sending messages defining a
    sandbox's configuration.
    """

    name: ClassVar[Final[str]] = "CONFIG_INFO_END"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerDeleteInprogressMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox is being deleted.
    """

    name: ClassVar[Final[str]] = "DELETE_INPROGRESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 1
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommServerDeleteSuccessMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox has been deleted.
    """

    name: ClassVar[Final[str]] = "DELETE_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerDeleteFailedMsg(SmdCommServerMsg):
    """
    Informs the client that deletion of a sandbox failed.
    """

    name: ClassVar[Final[str]] = "DELETE_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerCloneInprogressMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox is being cloned.
    """

    name: ClassVar[Final[str]] = "CLONE_INPROGRESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 3
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommServerCloneSuccessMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox has been cloned.
    """

    name: ClassVar[Final[str]] = "CLONE_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerCloneFailedMsg(SmdCommServerMsg):
    """
    Informs the client that cloning a sandbox failed.
    """

    name: ClassVar[Final[str]] = "CLONE_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerBootInprogressMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox is booting.
    """

    name: ClassVar[Final[str]] = "BOOT_INPROGRESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommServerBootSuccessMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox has been booted.
    """

    name: ClassVar[Final[str]] = "BOOT_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerBootFailedMsg(SmdCommServerMsg):
    """
    Informs the client that booting a sandbox failed.
    """

    name: ClassVar[Final[str]] = "BOOT_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerShutdownInprogressMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox is being shut down.
    """

    name: ClassVar[Final[str]] = "SHUTDOWN_INPROGRESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 2
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommServerShutdownSuccessMsg(SmdCommServerMsg):
    """
    Informs the client that a sandbox has been shut down.
    """

    name: ClassVar[Final[str]] = "SHUTDOWN_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerShutdownFailedMsg(SmdCommServerMsg):
    """
    Informs the client that shutting down a sandbox failed.
    """

    name: ClassVar[Final[str]] = "SHUTDOWN_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerCreateFileAckMsg(SmdCommServerMsg):
    """
    Informs the client that a file creation request has been accepted and the
    server is ready to receive file data.
    """

    name: ClassVar[Final[str]] = "CREATE_FILE_ACK"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerCreateFileSuccessMsg(SmdCommServerMsg):
    """
    Informs the client that a file has been created in a sandbox.
    """

    name: ClassVar[Final[str]] = "CREATE_FILE_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerCreateFileFailedMsg(SmdCommServerMsg):
    """
    Informs the client that a file creation operation failed.
    """

    name: ClassVar[Final[str]] = "CREATE_FILE_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = True

class SmdCommServerCreateDirSuccessMsg(SmdCommServerMsg):
    """
    Informs the client that a directory has been created in a sandbox.
    """

    name: ClassVar[Final[str]] = "CREATE_DIR_SUCCESS"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerCreateDirFailedMsg(SmdCommServerMsg):
    """
    Informs the client that a directory creation operation failed.
    """

    name: ClassVar[Final[str]] = "CREATE_DIR_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = True

class SmdCommServerListDirStartMsg(SmdCommServerMsg):
    """
    Informs the client that messages defining a directory's metadata and its
    directory listing are about to be sent.
    """

    name: ClassVar[Final[str]] = "LIST_DIR_START"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerListDirEntry(SmdCommServerMsg):
    """
    Provides file or directory metadata to the client as part of a directory
    listing.
    """

    name: ClassVar[Final[str]] = "LIST_DIR_ENTRY"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 5
    trailing_binary: ClassVar[Final[bool]] = True

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

class SmdCommServerListDirEndMsg(SmdCommServerMsg):
    """
    Informs the client that messages defining a directory's metadata and its
    directory listing are done being sent.
    """

    name: ClassVar[Final[str]] = "LIST_DIR_END"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerListDirFailedMsg(SmdCommServerMsg):
    """
    Informs the client that listing a directory failed.
    """

    name: ClassVar[Final[str]] = "LIST_DIR_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerReadFileStartMsg(SmdCommServerMsg):
    """
    Informs the frontend that the server is about to send it the contents of
    a file, and provides the file's metadata to the client.
    """

    name: ClassVar[Final[str]] = "READ_FILE_START"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 3
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommServerReadFileBlockMsg(SmdCommServerMsg):
    """
    Provides a block of a file to the client.
    """

    name: ClassVar[Final[str]] = "READ_FILE_BLOCK"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = True

class SmdCommServerReadFileEndMsg(SmdCommServerMsg):
    """
    Informs the client that a file has been fully sent.
    """

    name: ClassVar[Final[str]] = "READ_FILE_END"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerReadFileAbortAckMsg(SmdCommServerMsg):
    """
    Informs the client that a `READ_FILE_ABORT` message has been accepted and
    no further blocks of a file will be sent.
    """

    name: ClassVar[Final[str]] = "READ_FILE_ABORT_ACK"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerReadFileFailedMsg(SmdCommServerMsg):
    """
    Informs the client that the file read operation failed.
    """

    name: ClassVar[Final[str]] = "READ_FILE_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = True

class SmdCommServerListAppsStartMsg(SmdCommServerMsg):
    """
    Informs the client that the server is about to send an application list.
    """

    name: ClassVar[Final[str]] = "LIST_APPS_START"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerListAppsEntryMsg(SmdCommServerMsg):
    """
    Provides an application entry to the client.
    """

    name: ClassVar[Final[str]] = "LIST_APPS_ENTRY"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 3
    trailing_binary: ClassVar[Final[bool]] = False

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

class SmdCommServerListAppsEndMsg(SmdCommServerMsg):
    """
    Informs the client that the server is done sending an application list.
    """

    name: ClassVar[Final[str]] = "LIST_APPS_END"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = False

class SmdCommServerListAppsFailedMsg(SmdCommServerMsg):
    """
    Informs the client that the app listing operation failed.
    """

    name: ClassVar[Final[str]] = "LIST_APPS_FAILED"
    msg_code: ClassVar[Final[int]] = next_msg_code()
    arg_count: ClassVar[Final[int]] = 0
    trailing_binary: ClassVar[Final[bool]] = True
