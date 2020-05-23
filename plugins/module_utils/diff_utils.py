# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import operator


def attr_diff(params, name, remote, equal=operator.eq, report_none=False):
    """
    :type params: dict
    :type name: str
    :type remote: typing.Any
    :type equal: function
    :type report_none: bool
    :rtype: dict
    """
    diff = {}
    desired = params[name]

    if not equal(desired, remote):
        # Parameter may be omitted and its value defaults to None.
        # This typically means that it should not be considered in diff.
        # However, sometimes we want this to be reported in the diff.
        if report_none or desired is not None:
            diff['before'] = remote
            diff['after'] = desired
    return diff
