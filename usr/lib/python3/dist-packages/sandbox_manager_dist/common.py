#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

"""
common.py - Common functions and definitions used throughout
sandbox-manager-dist.
"""

import re
import pwd
from pathlib import Path
from typing import Callable
from enum import Enum


class SmdValidateType(Enum):
    """
    Enum for selecting what kind of value to validate, used by
    SmdCommon.validate_id().
    """

    USER_NAME = 1
    UUID = 2
    SANDBOX_NAME = 3
    BOOT_MODE = 4
    SHUTDOWN_MODE = 5
    FILE_PERM = 6
    ABSOLUTE_PATH = 7
    # RELATIVE_PATH = 8
    DESKTOP_FILE = 9
    FILE_TYPE = 10
    FILE_NAME = 11
    DECIMAL_INT = 12
    YN_BOOL = 13
    WRITE_STATUS = 14
    DEVICE_PATH = 15


class SmdSocketType(Enum):
    """
    Enum for defining socket type.
    """

    CONTROL = 1
    COMMUNICATION = 2


class SmdSandboxStatus(Enum):
    """
    Specifies a sandbox's current status (i.e. is it booting up, shutting down,
    actively being created, etc.).
    """

    SHUT_DOWN = 1
    BOOTING_UPDATE = 2
    BOOTING_WORK = 3
    BOOTED_UPDATE = 4
    BOOTED_WORK = 5
    SHUTTING_DOWN = 6
    CONFIG = 7
    CREATE = 8
    DELETE = 9
    CLONE = 10


class SmdCommon:
    """
    Common functionality class.
    """

    state_dir: Path = Path("/run/sandbox-manager-dist")
    sandbox_dir: Path = Path("/home/sandbox-manager-dist")
    sandbox_root_file: str = "root.img"
    sandbox_data_file: str = "data.img"
    sandbox_config_file: str = "config"
    control_path: Path = Path(state_dir, "control")
    comm_dir: Path = Path(state_dir, "comm")

    user_name_regex: re.Pattern[str] = re.compile(r"[a-z_][-a-z0-9_]*\$?\Z")
    uuid_regex: re.Pattern[str] = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
    )
    sandbox_name_regex: re.Pattern[str] = re.compile(r"[-_a-zA-Z0-9 ]+\Z")
    boot_mode_regex: re.Pattern[str] = re.compile(r"(work|update)\Z")
    shutdown_mode_regex: re.Pattern[str] = re.compile(r"(shutdown|kill)\Z")
    file_perm_regex: re.Pattern[str] = re.compile(r"[0-7]{4}\Z")
    absolute_path_regex: re.Pattern[str] = re.compile(r"/[^\x00]*\Z")
    device_path_regex: re.Pattern[str] = re.compile(r"/dev/[^\x00]+\Z")
    # relative_path_regex: re.Pattern[str] = re.compile(r"[^\x00]+\Z")
    desktop_file_regex: re.Pattern[str] = re.compile(r".+\.desktop\Z")
    file_type_regex: re.Pattern[str] = re.compile(r"(f|d)\Z")
    file_name_regex: re.Pattern[str] = re.compile(r"[^\x00/]+\Z")
    decimal_int_regex: re.Pattern[str] = re.compile(r"[0-9]+\Z")
    yn_bool_regex: re.Pattern[str] = re.compile(r"(y|n)\Z")
    write_status_regex: re.Pattern[str] = re.compile(r"(RW|RO)\Z")
    max_vol_size: int = (16 * 1024 * 1024 * 1024 * 1024) - 4096
    max_mem_size: int = 1024 * 1024 * 1024 * 1024
    max_cpu_weight: int = 10000
    max_io_weight: int = 10000
    correlation_id_bound: int = 2**128

    @staticmethod
    def validate_id(
        id_string: str, validate_arr: list[SmdValidateType], err_str: str
    ) -> None:
        """
        Validates id_string against one or more predefined regexes. Raises a
        ValueError if id_string does not match any of the regexes specified by
        validate_arr or if id_string is too long.
        """

        if len(id_string) > 100:
            raise ValueError("id_string too long")

        validation_passed: bool = False

        for validate_type in validate_arr:
            target_regex: re.Pattern[str] | None = None
            ## FIXME: func_handler is unused, remove it if we don't end up with
            ## a use for it later
            func_handler: Callable[[str], bool] | None = None
            match validate_type:
                case SmdValidateType.USER_NAME:
                    target_regex = SmdCommon.user_name_regex
                case SmdValidateType.UUID:
                    target_regex = SmdCommon.uuid_regex
                case SmdValidateType.SANDBOX_NAME:
                    target_regex = SmdCommon.sandbox_name_regex
                case SmdValidateType.BOOT_MODE:
                    target_regex = SmdCommon.boot_mode_regex
                case SmdValidateType.SHUTDOWN_MODE:
                    target_regex = SmdCommon.shutdown_mode_regex
                case SmdValidateType.FILE_PERM:
                    target_regex = SmdCommon.file_perm_regex
                case SmdValidateType.ABSOLUTE_PATH:
                    target_regex = SmdCommon.absolute_path_regex
                # case SmdValidateType.RELATIVE_PATH:
                #    target_regex = SmdCommon.relative_path_regex
                case SmdValidateType.DEVICE_PATH:
                    target_regex = SmdCommon.device_path_regex
                case SmdValidateType.DESKTOP_FILE:
                    target_regex = SmdCommon.desktop_file_regex
                case SmdValidateType.FILE_TYPE:
                    target_regex = SmdCommon.file_type_regex
                case SmdValidateType.FILE_NAME:
                    target_regex = SmdCommon.file_name_regex
                case SmdValidateType.DECIMAL_INT:
                    target_regex = SmdCommon.decimal_int_regex
                case SmdValidateType.YN_BOOL:
                    target_regex = SmdCommon.yn_bool_regex
                case SmdValidateType.WRITE_STATUS:
                    target_regex = SmdCommon.write_status_regex

            if func_handler is None:
                if target_regex.match(id_string):
                    validation_passed = True
                    break
            else:
                if func_handler(id_string):
                    validation_passed = True
                    break

        if not validation_passed:
            raise ValueError(err_str)

    @staticmethod
    def normalize_user_id(user_id: str) -> int | None:
        """
        Ensures the user with the specified name or UID exists on the system.
        Returns None if the user doesn't exist, or the UID if the user exists.
        """

        try:
            SmdCommon.validate_id(user_id, [SmdValidateType.USER_NAME], "")
            user_info_list: list[pwd.struct_passwd] = pwd.getpwall()
            for user_info in user_info_list:
                if user_info.pw_name == user_id:
                    return user_info.pw_uid
        except ValueError:
            pass

        try:
            SmdCommon.validate_id(user_id, [SmdValidateType.DECIMAL_INT], "")
            user_id_numeric: int = int(user_id)
            uid_list: list[int] = [pw.pw_uid for pw in pwd.getpwall()]
            if user_id_numeric in uid_list:
                return user_id_numeric
        except ValueError:
            pass

        return None
