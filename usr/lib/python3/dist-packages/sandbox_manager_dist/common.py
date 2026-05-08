#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

"""
common.py - Common functions and definitions used throughout
sandbox-manager-dist.
"""

import re
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
    RELATIVE_PATH = 9
    DESKTOP_FILE = 10
    FILE_TYPE = 11
    FILE_NAME = 12

class SmdCommon:
    """
    Common functionality class.
    """

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
    relative_path_regex: re.Pattern[str] = re.compile(r"[^\x00]+\Z")
    desktop_file_regex: re.Pattern[str] = re.compile(r".+\.desktop\Z")
    file_type_regex: re.Pattern[str] = re.compile(r"(f|d)\Z")
    file_name_regex: re.Pattern[str] = re.compile(r"[^\x00/]+\z")

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
                case SmdValidateType.RELATIVE_PATH:
                    target_regex = SmdCommon.relative_path_regex
                case SmdValidateType.DESKTOP_FILE:
                    target_regex = SmdCommon.desktop_file_regex
                case SmdValidateType.FILE_TYPE:
                    target_regex = SmdCommon.file_type_regex
                case SmdValidateType.FILE_NAME:
                    target_regex = SmdCommon.file_name_regex

            if target_regex.match(id_string):
                validation_passed = True
                break

        if not validation_passed:
            raise ValueError(err_str)
