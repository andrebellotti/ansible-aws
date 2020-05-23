# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.steampunk.aws.plugins.module_utils import (
    ec2_filters, errors, boto, tag_utils
)


def result_from_resource(vpc):
    """
    :type boto_dict: dict
    :rtype: dict
    """
    return dict(
        id=vpc.id,
        cidr=vpc.cidr_block,
        instance_tenancy=vpc.instance_tenancy,
        tags=tag_utils.from_boto3(vpc.tags if vpc.tags is not None else [])
    )


def get_default_vpc(ec2):
    """
    Retrieves the default VPC.

    :raises errors.ObjectDoesNotExist: when the default VPC does not exist.
    """
    vpc_collection = ec2.vpcs.filter(
        Filters=ec2_filters.from_dict(dict(
            isDefault='true',
        ))
    )
    vpcs = list(vpc_collection)
    if not vpcs:  # we don't have a default VPC
        raise errors.ObjectDoesNotExist(
            "Default VPC does not exist. Create one or pass "
            "the VPC id via 'vpc' parameter."
        )
    # we cannot have more than one default VPC per region
    vpc = vpcs[0]
    vpc.load()

    return vpc


def get_vpc_by_id(ec2, vpc_id, fail_nonexisting_id=False):
    """
    Retrieves a VPC with an ID of vpc_id or optionally fails when it does not exist.

    :raises errors.ObjectDoesNotExist: when a VPC with id vpc_id does not exist.
    """
    vpc = ec2.Vpc(vpc_id)
    try:
        vpc.load()
    except boto.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidVpcID.NotFound':
            if fail_nonexisting_id:
                raise errors.ObjectDoesNotExist('VPC with id {0} does not exist'.format(vpc_id))
            return None
        raise
    return vpc


def get_vpc(ec2, vpc_id):
    """
    When vpc_id is set, it returns the referenced VPC.
    Otherwise returns the default VPC.

    :raises errors.ObjectDoesNotExist: when vpc_id is given but VPC does not
    exist, or when vpc_id is None but default VPC does not exist.
    """
    if not vpc_id:
        return get_default_vpc(ec2)
    return get_vpc_by_id(ec2, vpc_id, fail_nonexisting_id=True)
