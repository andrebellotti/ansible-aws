# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.steampunk.aws.plugins.module_utils import (
    errors
)


def validate_presence(required, params):
    """
    Validates the presence of the required keys in params dict.

    :type required: typing.List[str]
    :type params: dict
    :raises errors.ValidationError: when any of the required keys are
            missing from params.
    """
    provided = [p for p in params.keys() if params[p]]
    missing = set(required) - set(provided)
    if missing:
        raise errors.ValidationError(
            "Missing required parameters: '{0}'".format(
                ", ".join(missing)
            )
        )


def validate_update(immutable, diff):
    """
    Validates the update by making sure we're not trying to modify an immutable
    property. Param immutable contains the names of immutable properties.
    Param diff contains diff with properties to modify as keys.

    :type immutable: typing.List[str]
    :type diff: dict
    :raises errors.ValidationError: when trying to update immutable properties.
    """
    cannot_update = set(immutable).intersection(diff)
    if cannot_update:
        raise errors.ValidationError(
            'Trying to update immutable properties: {0}'.format(
                ", ".join(cannot_update)
            )
        )
