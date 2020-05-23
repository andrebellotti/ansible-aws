# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = """
options:
  clear_tags:
    description:
      - Whether to clear any existing tags on the resource that
        are not explicitly stated in I(tags).
      - By default, existing tags are kept on the resource.
      - When this parameter is set to C(true), any pre-existing tags
        on the resource (including the name tag) are removed.
        To clear all tags except the name tag, make sure to provide
        the I(name) parameter.
    type: bool
    default: false
"""
