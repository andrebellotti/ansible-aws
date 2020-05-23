# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.steampunk.aws.plugins.module_utils import (
    tag_utils, errors,
)


def result_from_params(gateway_id, vpc_id, name, tags):
    return dict(
        id=gateway_id,
        vpc=vpc_id,
        tags=tag_utils.merge_with_name_param(name, tags),
    )


def result_from_remote(gateway):
    vpc_id = None
    if gateway.attachments:
        if len(gateway.attachments) > 1:
            raise errors.UnexpectedStateError(
                'More than one VPC attachment exists'
            )
        vpc_id = gateway.attachments[0]['VpcId']

    return result_from_params(
        gateway.id, vpc_id, None, tag_utils.from_boto3(gateway.tags)
    )
