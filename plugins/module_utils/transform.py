# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def dict_to_list_of_structured_dicts(data, key_name, val_name):
    """
    {key: value, ..} -> [{key_name: key, val_name: value}, ...]

    :type data: dict
    :type key_name: str
    :type val_name: str
    :rtype: typing.List[dict]
    """
    return [
        {key_name: k, val_name: v}
        for k, v in data.items()
    ]


def list_of_structured_dicts_to_dict(data, key_name, val_name):
    """
    [{key_name: key, val_name: value}, ...] -> {key: value, ..}

    :type data: typing.List[dict]
    :type key_name: str
    :type val_name: str
    :rtype: dict
    """
    res = dict()
    for i in data:
        res[i[key_name]] = i[val_name]
    return res
