#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

"""
protocol.py - Defines protocol messages used for communication between the
frontend, backend, and agent.
"""

from .common import (
    SmdValidateType,
    SmdCommon,
)

## This is incremented by one before defining each message derived class so
## that there are never two messages with the same code. This does mean if we
## insert a message into the middle of the class definitions, it will shift
## the message codes around, but this protocol is used purely internally, so
## that isn't a problem.
##
## TODO: Can we somehow do this at package build time to avoid wasting
## resources?
msg_inc_int: int = 0

class SmdBaseMsg:
    """
    Base class for all message classes.
    """

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None,
        binary_blob: bytes | None,
    ) -> None:
        """
        Bundles together the information in a message.
        """

        self._name: str = ""
        self._msg_code: int = 0
        self._arg_count: int = 0
        self._trailing_binary: bool = False

        ## WARNING: The base class does NOT validate its parameters via
        ## SmdBaseMsg.validate_msg_params()! Derived classes are expected to
        ## do this, since they need to anyway to safely apply their own
        ## validation.

        self.correlation_id: int = correlation_id
        self.arg_list: list[str] = arg_list if arg_list is not None else []
        self.binary_blob: bytes = (
            binary_blob if binary_blob is not None else b""
        )

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

    @property
    def name(self) -> str:
        """
        The message name. Not part of the wire protocol, but used in log
        messages and exceptions.
        """

        return self._name

    @name.setter
    def name(self, value: str) -> None:
        """
        "name" setter.
        """

        self._name = value

    @name.deleter
    def name(self) -> None:
        """
        "name" deleter.
        """

        del self._name

    @property
    def msg_code(self) -> int:
        """
        The message code. Uniquely identifies the message in the protocol.
        """

        return self._msg_code

    @msg_code.setter
    def msg_code(self, value: int) -> None:
        """
        "msg_code" setter.
        """

        self._msg_code = value

    @msg_code.deleter
    def msg_code(self) -> None:
        """
        "msg_code" deleter.
        """

        del self._msg_code

    @property
    def arg_count(self) -> int:
        """
        Message argument count. Used for validation when creating message
        objects.
        """

        return self._arg_count

    @arg_count.setter
    def arg_count(self, value: int) -> None:
        """
        "arg_count" setter.
        """

        self._arg_count = value

    @arg_count.deleter
    def arg_count(self) -> None:
        """
        "arg_count" deleter.
        """

        del self._arg_count

    @property
    def trailing_binary(self) -> bool:
        """
        Whether the message includes a trailing binary blob or not. Also used
        in validation.
        """

        return self._trailing_binary

    @trailing_binary.setter
    def trailing_binary(self, value: bool) -> None:
        """
        "trailing_binary" setter.
        """

        self._trailing_binary = value

    @trailing_binary.deleter
    def trailing_binary(self) -> None:
        """
        "trailing_binary" deleter.
        """

        del self._trailing_binary

    def validate_msg_params(
        self,
        correlation_id: int,
        arg_list: list[str] | None,
        binary_blob: bytes | None,
    ) -> None:
        """
        Shared validation logic to make sure the right parameters are passed
        when constructing a message object. Raises a ValueError if validation
        fails.
        """

        if not 0 <= correlation_id <= ((2 ** 128) - 1):
            raise ValueError(
                "Correlation ID out of range for a 128-bit unsigned integer"
            )

        if arg_list is None and self.arg_count != 0:
            raise ValueError(
                f"No argument list provided for {self.name}, but arguments "
                + "are required"
            )

        if arg_list is None and self.arg_count != 0:
            raise ValueError(
                f"No arguments provided for {self.name} but arguments were "
                "expected"
            )

        if arg_list is not None and len(arg_list) != self.arg_count:
            raise ValueError(f"Incorrect number of arguments for {self.name}")

        if (
            binary_blob is not None
            and len(binary_blob) != 0
            and not self.trailing_binary
        ):
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

msg_inc_int += 1
class SmdControlClientRegisterMsg(SmdControlClientMsg):
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

        self.name: str = "REGISTER"
        self.msg_code: int = msg_inc_int
        self.arg_count: int = 1
        self.trailing_binary: bool = False

        self.validate_msg_params(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.USER_NAME],
            "User name failed validation",
        )
        super().__init__(correlation_id, arg_list, binary_blob)

msg_inc_int += 1
class SmdControlClientUnregisterMsg(SmdControlClientMsg):
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

        self.name: str = "UNREGISTER"
        self.msg_code: int = msg_inc_int
        self.arg_count: int = 1
        self.trailing_binary: bool = False

        self.validate_msg_params(correlation_id, arg_list, binary_blob)
        assert arg_list is not None
        SmdCommon.validate_id(
            arg_list[0],
            [SmdValidateType.USER_NAME],
            "User name failed validation",
        )
        super().__init__(correlation_id, arg_list, binary_blob)

msg_inc_int += 1
class SmdControlServerRegisterSuccessMsg(SmdControlServerMsg):
    """
    Informs the client that comm socket creation has succeeded.
    """

    name: str = "REGISTER_SUCCESS"
    msg_code: int = msg_inc_int
    arg_count: int = 0
    trailing_binary: bool = False

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        REGISTER_SUCCESS init function.
        """

        self.validate_msg_params(correlation_id, arg_list, binary_blob)
        super().__init__(correlation_id, arg_list, binary_blob)

msg_inc_int += 1
class SmdControlServerRegisterExistsMsg(SmdControlServerMsg):
    """
    Informs the client that the comm socket already exists.
    """

    name: str = "REGISTER_EXISTS"
    msg_code: int = msg_inc_int
    arg_count: int = 0
    trailing_binary: bool = False

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        REGISTER_EXISTS init function.
        """

        self.validate_msg_params(correlation_id, arg_list, binary_blob)
        super().__init__(correlation_id, arg_list, binary_blob)

msg_inc_int += 1
class SmdControlServerRegisterFailureMsg(SmdControlServerMsg):
    """
    Informs the client that the comm socket could not be created.
    """

    name: str = "REGISTER_FAILURE"
    msg_code: int = msg_inc_int
    arg_count: int = 0
    trailing_binary: bool = False

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        REGISTER_FAILURE init function.
        """

        self.validate_msg_params(correlation_id, arg_list, binary_blob)
        super().__init__(correlation_id, arg_list, binary_blob)

msg_inc_int += 1
class SmdControlServerUnregisterSuccessMsg(SmdControlServerMsg):
    """
    Informs the client that comm socket removal has succeeded.
    """

    name: str = "UNREGISTER_SUCCESS"
    msg_code: int = msg_inc_int
    arg_count: int = 0
    trailing_binary: bool = False

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        UNREGISTER_SUCCESS init function.
        """

        self.validate_msg_params(correlation_id, arg_list, binary_blob)
        super().__init__(correlation_id, arg_list, binary_blob)

msg_inc_int += 1
class SmdControlServerUnregisterAbsentMsg(SmdControlServerMsg):
    """
    Informs the client that the comm socket does not exist.
    """

    name: str = "UNREGISTER_ABSENT"
    msg_code: int = msg_inc_int
    arg_count: int = 0
    trailing_binary: bool = False

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        UNREGISTER_ABSENT init function.
        """

        self.validate_msg_params(correlation_id, arg_list, binary_blob)
        super().__init__(correlation_id, arg_list, binary_blob)

msg_inc_int += 1
class SmdControlServerUnregisterFailureMsg(SmdControlServerMsg):
    """
    Informs the client that the comm socket could not be removed.
    """

    name: str = "UNREGISTER_FAILURE"
    msg_code: int = msg_inc_int
    arg_count: int = 0
    trailing_binary: bool = False

    def __init__(
        self,
        correlation_id: int,
        arg_list: list[str] | None = None,
        binary_blob: bytes | None = None,
    ) -> None:
        """
        UNREGISTER_FAILURE init function.
        """

        self.validate_msg_params(correlation_id, arg_list, binary_blob)
        super().__init__(correlation_id, arg_list, binary_blob)
