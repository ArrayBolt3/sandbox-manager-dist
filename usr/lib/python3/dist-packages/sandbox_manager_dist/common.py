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
    USER_UID = 2
    UUID = 3
    SANDBOX_NAME = 4
    BOOT_MODE = 5
    SHUTDOWN_MODE = 6
    FILE_PERM = 7
    ABSOLUTE_PATH = 8
    # RELATIVE_PATH = 9
    DESKTOP_FILE = 10
    FILE_TYPE = 11
    FILE_NAME = 12
    DECIMAL_INT = 13
    YN_BOOL = 14
    WRITE_STATUS = 15


class SmdSocketType(Enum):
    """
    Enum for defining socket type.
    """

    CONTROL = 1
    COMMUNICATION = 2


class SmdCommon:
    """
    Common functionality class.
    """

    state_dir: Path = Path("/run/sandbox-manager-dist")
    control_path: Path = Path(state_dir, "control")
    comm_dir: Path = Path(state_dir, "comm")

    user_name_regex: re.Pattern[str] = re.compile(r"[a-z_][-a-z0-9_]*\$?\Z")
    uid_regex: re.Pattern[str] = re.compile(r"[0-9]+\Z")
    uuid_regex: re.Pattern[str] = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
    )
    sandbox_name_regex: re.Pattern[str] = re.compile(r"[-_a-zA-Z0-9 ]+\Z")
    boot_mode_regex: re.Pattern[str] = re.compile(r"(work|update)\Z")
    shutdown_mode_regex: re.Pattern[str] = re.compile(r"(shutdown|kill)\Z")
    file_perm_regex: re.Pattern[str] = re.compile(r"[0-7]{4}\Z")
    absolute_path_regex: re.Pattern[str] = re.compile(r"/[^\x00]*\Z")
    # relative_path_regex: re.Pattern[str] = re.compile(r"[^\x00]+\Z")
    desktop_file_regex: re.Pattern[str] = re.compile(r".+\.desktop\Z")
    file_type_regex: re.Pattern[str] = re.compile(r"(f|d)\Z")
    file_name_regex: re.Pattern[str] = re.compile(r"[^\x00/]+\Z")
    decimal_int_regex: re.Pattern[str] = re.compile(r"[0-9]+\Z")
    yn_bool_regex: re.Pattern[str] = re.compile(r"(y|n)\Z")
    write_status_regex: re.Pattern[str] = re.compile(r"(RW|RO)\Z")

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
                case SmdValidateType.USER_UID:
                    target_regex = SmdCommon.uid_regex
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
    def normalize_user_id(user_name: str) -> str | None:
        """
        Ensures the user with the specified name or UID exists on the system.
        Returns None if the user doesn't exist, or the username if the user
        does exist.
        """

        try:
            SmdCommon.validate_id(user_name, [SmdValidateType.USER_NAME], "")
            user_list: list[str] = [pw.pw_name for pw in pwd.getpwall()]
            if user_name in user_list:
                return user_name
        except ValueError:
            pass

        try:
            SmdCommon.validate_id(user_name, [SmdValidateType.DECIMAL_INT], "")
            uid_list: list[str] = [str(pw.pw_uid) for pw in pwd.getpwall()]
            if user_name in uid_list:
                return pwd.getpwuid(int(user_name)).pw_name
        except ValueError:
            pass

        return None
