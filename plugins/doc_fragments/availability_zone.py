# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = """
options:
  availability_zone:
    description:
      - ID of the availability zone to create the AWS resource in.
      - If omitted, the availability zone will be selected by AWS.
    type: str
"""
