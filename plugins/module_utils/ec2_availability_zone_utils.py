# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.


from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.steampunk.aws.plugins.module_utils import boto, errors


def validate_az_id(ec2, availability_zone_id):
    try:
        ec2.meta.client.describe_availability_zones(
            ZoneIds=[availability_zone_id]
        )
    except boto.ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAvailabilityZone", "InvalidParameterValue"):
            raise errors.ObjectDoesNotExist(
                "Availability zone with id {0} does not "
                "exist in your region".format(availability_zone_id)
            )
        raise
