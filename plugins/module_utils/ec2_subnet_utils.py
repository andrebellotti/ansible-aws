# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.


from __future__ import absolute_import, division, print_function

__metaclass__ = type


from ansible_collections.steampunk.aws.plugins.module_utils import ec2_filters, errors, tag_utils


def result_from_resource(subnet):
    return dict(
        id=subnet.id,
        vpc=subnet.vpc_id,
        availability_zone=subnet.availability_zone_id,
        cidr=subnet.cidr_block,
        auto_assign_ip=subnet.map_public_ip_on_launch,
        tags=tag_utils.from_boto3(subnet.tags if subnet.tags is not None else []),
        available_ip_address_count=subnet.available_ip_address_count
    )


def get_subnet_by_id(ec2, subnet_id, fail_nonexisting_id=False):
    subnet = ec2.Subnet(subnet_id)
    if subnet not in ec2.subnets.filter(
            Filters=ec2_filters.from_dict({
                'subnet-id': subnet_id,
            })
    ):
        if fail_nonexisting_id:
            raise errors.ObjectDoesNotExist(
                'Subnet with id {0} does not exist'.format(subnet_id)
            )
        return None

    subnet.load()

    return subnet


def get_default_subnet_for_az(ec2, availability_zone_id):
    subnet_collection = ec2.subnets.filter(
        Filters=ec2_filters.from_dict({
            'availability-zone-id': availability_zone_id,
            'default-for-az': 'true',
        })
    )
    subnets = list(subnet_collection)

    if not subnets:
        raise errors.ObjectDoesNotExist(
            'Availability zone with id {0} does not'
            ' have a default subnet'.format(availability_zone_id)
        )

    # there can't be more than 1 default subnet per AZ
    subnet = subnets[0]
    subnet.load()

    return subnet
