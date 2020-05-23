# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.steampunk.aws.plugins.module_utils import (
    transform
)


def from_dict(data):
    """
    :type data: dict
    :rtype: typing.List[dict]
    """
    data_with_list_vals = {}
    for k, v in data.items():
        if not isinstance(v, list):
            v = [v]  # Make sure we're passing values as lists
        data_with_list_vals[k] = v
    return transform.dict_to_list_of_structured_dicts(
        data_with_list_vals, 'Name', 'Values')


def mapping_for_params(*param_names):
    mapping = {}
    for p in param_names:
        mapping[p] = _COMMON[p]

    return mapping


# Common mappings from module parameter names to boto3 filters.
_COMMON = dict(
    names='tag:Name',
)


def build_from_mapping(mapping, module_params):
    """
    Given a mapping
        module_param_name -> filter_name
    and module_params
        module_param_name -> module_param_val
    builds the payload that can be used by the info modules
    as the 'Filters' argument directly.

    :type mapping: dict
    :type module_params: dict
    :rtype: typing.List[dict]
    """
    filters = module_params.get('filters', {})
    for param in module_params:
        if param != 'filters' and module_params[param] and param in mapping:
            filters[mapping[param]] = module_params[param]
    return from_dict(filters)
