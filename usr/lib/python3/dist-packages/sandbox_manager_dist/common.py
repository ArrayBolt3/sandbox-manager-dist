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

class SmdCommon:
    """
    Common functionality class.
    """

    user_name_regex: re.Pattern[str] = re.compile(r"[a-z_][-a-z0-9_]*\$?\Z")
    uid_regex: re.Pattern[str] = re.compile(r"[0-9]+\Z")

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
            if validate_type is SmdValidateType.USER_NAME:
                target_regex = SmdCommon.user_name_regex
            elif validate_type is SmdValidateType.USER_UID:
                target_regex = SmdCommon.uid_regex

            if target_regex.match(id_string):
                validation_passed = True
                break

        if not validation_passed:
            raise ValueError(err_str)
