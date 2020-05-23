#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "XLAB Steampunk",
}

# language=yaml
DOCUMENTATION = """
module: ec2_subnet
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: Manage EC2 VPC Subnets
description:
  -  Create, update or delete an AWS EC2 VPC Subnet.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.availability_zone
  - steampunk.aws.state
  - steampunk.aws.id
  - steampunk.aws.tags
  - steampunk.aws.clear_tags
options:
  name:
    description:
      - Name of the subnet.
      - This parameter is required when first creating the subnet.
    type: str
  vpc:
    description:
      - ID of the VPC for the target subnet.
      - In the absence of I(id), the value of this parameter will be
        used to uniquely identify the subnet together wit I(cidr).
      - If omitted, the default VPC is assumed.
    type: str
  cidr:
    description:
      - IPv4 network range to assign to the subnet, in CIDR notation.
      - This parameter is required unless I(id) is provided.
      - In the absence of I(id), the value of this parameter will be
        used to uniquely identify the subnet within the desired I(vpc)
        or default VPC.
    type: str
  auto_assign_ip:
    description:
      - Whether a public IPv4 address should be assigned to ENIs attached to
        instances launched from this subnet.
    type: bool
    default: false
seealso:
  - module: ec2_subnet_info
"""

# language=yaml
EXAMPLES = """
- name: Create a subnet in the default VPC
  ec2_subnet:
    name: my-subnet-in-default-vpc
    cidr: 10.0.0.0/16

- name: Create a subnet in a non-default VPC and specific availability zone
  ec2_subnet:
    name: my-subnet
    vpc: vpc-123456
    cidr: 10.0.0.0/16
    availability_zone: use2-az2
  register: my_subnet

- name: Update the subnet's setting for auto assigning public IPs to instances
  ec2_subnet:
    id: "{{ my_subnet.object.id }}"
    auto_assign_ip: true

- name: Clear all the subnet's tags
  ec2_subnet:
    id: "{{ my_subnet.object.id }}"
    clear_tags: true

- name: Delete a subnet
  ec2_subnet:
    id: "{{ my_subnet.object.id }}"
    state: absent

- name: Delete a subnet in a non-default VPC by providing a VPC ID and subnet CIDR block
  ec2_subnet:
    vpc: vpc-123456
    cidr: 10.0.0.0/16
    state: absent

- name: Delete a subnet in the default VPC by providing its CIDR block
  ec2_subnet:
    cidr: 10.0.0.0/16
    state: absent
"""

# language=yaml
RETURN = """
object:
  description:
    - An object representing an EC2 subnet.
  type: dict
  returned: success and I(state=present)
  contains:
    id:
      description: The ID of the subnet.
      type: str
      returned: always
    vpc:
      description: The ID of the VPC the subnet belongs to.
      type: str
      returned: always
    availability_zone:
      description: The ID of the availability zone the subnet is in.
      type: str
      returned: always
    cidr:
      description: The CIDR block of the subnet.
      type: str
      returned: always
    auto_assign_ip:
      description: Whether a public IPv4 address is automatically assigned
                   to instances in this subnet.
      type: bool
      returned: always
    tags:
      description: The tags assigned to the subnet.
      type: dict
      returned: always
    available_ip_address_count:
      description: The number of remaining private IPv4 addresses in the range of the subnet.
      type: int
      returned: always
  sample:
    object:
      id: subnet-123456
      vpc: vpc-123456
      availability_zone: eun-az1
      cidr: "192.0.2.0/24"
      auto_assign_ip: true
      tags:
        mycompany-public: true
      available_ip_address_count: 15
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, tag_utils, validation, errors, diff_utils, ec2_vpc_utils, ec2_filters,
    ec2_subnet_utils, ec2_availability_zone_utils
)


def identify_subnet(ec2, subnet_id, vpc_id, cidr, **kwargs):
    if subnet_id:
        return ec2_subnet_utils.get_subnet_by_id(ec2, subnet_id, **kwargs)
    return get_subnet_by_cidr_and_vpc(ec2, cidr, vpc_id)


def get_subnet_by_cidr_and_vpc(ec2, cidr, vpc_id):
    # vpc id was not provided, assume default VPC
    if not vpc_id:
        default_vpc = ec2_vpc_utils.get_default_vpc(ec2)
        vpc_id = default_vpc.id

    subnet_collection = ec2.subnets.filter(
        Filters=ec2_filters.from_dict({
            'cidr': cidr,
            'vpc-id': vpc_id,
        }))

    subnets = list(subnet_collection)

    if not subnets:
        return None

    # vpc id + subnet cidr uniquely identify the subnet.
    # subnet cidr blocks are unique and non-overlapping in the scope of a VPC.
    # This is why we don't need to handle the case when there is more than
    # one subnet.
    subnet = subnets[0]
    subnet.load()

    return subnet


def subnets_diff(params, remote):
    diff = {}
    for (param_name, remote_val) in [
        ('vpc', remote.vpc.id),
        ('cidr', remote.cidr_block),
        ('auto_assign_ip', remote.map_public_ip_on_launch),
        ('availability_zone', remote.availability_zone_id),
    ]:
        attribute_diff = diff_utils.attr_diff(params, param_name, remote_val)
        if attribute_diff:
            diff[param_name] = attribute_diff

    return diff


def handle_absent(ec2_resource, params, check_mode):
    subnet = identify_subnet(ec2_resource,
                             params['id'], params['vpc'], params['cidr'])
    if not subnet:  # trying to delete a non-existing subnet
        return False, None, None

    return delete(subnet, check_mode)


def delete(subnet, check_mode):
    if not check_mode:
        before = ec2_subnet_utils.result_from_resource(subnet)
        subnet.delete()
        return True, None, dict(
            before=before,
            after=dict(),
        )
    return True, None, None


def check_update(subnet, params):
    """ Checks if update is necessary, and if it is,
        reports what needs to be updated.
    """
    diff = subnets_diff(params, subnet)

    current_tags = tag_utils.from_boto3(subnet.tags)
    tag_diff = tag_utils.get_diff(params['name'], params['tags'], current_tags)
    tags_to_update, tags_to_remove = tag_utils.from_diff(
        tag_diff, clear_existing=params['clear_tags']
    )

    # they don't differ, do nothing
    to_update = diff or tags_to_update or tags_to_remove

    return to_update, diff, tag_diff


def handle_create(ec2_resource, params, check_mode):
    validate_creation_params(params)
    return create(ec2_resource, params, check_mode)


def handle_update(subnet, params, check_mode):
    # check if it needs updating at all
    to_update, diff, tag_diff = check_update(subnet, params)
    if not to_update:
        return False, subnet, None

    # validate and perform the update
    immutable_params = [
        'vpc',
        'cidr',
        'availability_zone'
    ]
    validation.validate_update(immutable_params, diff)
    return update(subnet, diff, tag_diff, params, check_mode)


def handle_present(ec2_resource, params, check_mode):
    subnet = identify_subnet(ec2_resource,
                             params['id'], params['vpc'], params['cidr'],
                             fail_nonexisting_id=True)

    if not subnet:
        return handle_create(ec2_resource, params, check_mode)

    return handle_update(subnet, params, check_mode)


def validate_creation_params(params):
    required = {'name', 'cidr'}
    provided = set([p for p in params.keys() if params[p]])
    missing = required - provided
    if missing:
        raise errors.ValidationError(
            "Missing required parameters: '{0}'".format(missing)
        )


def create(ec2, params, check_mode):
    if check_mode:
        return True, None, None

    vpc = ec2_vpc_utils.get_vpc(ec2, params["vpc"])

    payload = dict(
        CidrBlock=params['cidr'],
    )
    if params['availability_zone']:
        ec2_availability_zone_utils.validate_az_id(ec2, params['availability_zone'])
        payload['AvailabilityZoneId'] = params['availability_zone']

    try:
        subnet = vpc.create_subnet(**payload)
    except boto.ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidSubnet.Range":
            raise errors.ValidationError("Invalid subnet range: the block size must be between "
                                         "a /28 netmask and /16 netmask.")
        elif code == "InvalidSubnet.Conflict":
            raise errors.ValidationError("Invalid subnet range: the specified CIDR block "
                                         "conflicts with that of another subnet in your VPC.")
        elif code == "InvalidParameterValue":
            raise errors.ValidationError(e.response["Error"]["Message"])
        raise

    subnet_waiter = subnet.meta.client.get_waiter('subnet_available')
    subnet_waiter.wait(SubnetIds=[subnet.id])

    # we cannot tag the subnet at the time of creation,
    # so we do it in a separate call
    subnet.create_tags(
        Tags=tag_utils.to_boto3(params['tags'], name=params['name']),
    )
    if subnet.map_public_ip_on_launch != params['auto_assign_ip']:
        subnet.meta.client.modify_subnet_attribute(
            SubnetId=subnet.id,
            MapPublicIpOnLaunch=dict(
                Value=params['auto_assign_ip'],
            ),
        )

    # get the up-to-date representation with correct state and tags
    subnet.reload()

    return True, subnet, dict(
        before=dict(),
        after=ec2_subnet_utils.result_from_resource(subnet),
    )


def update(subnet, diff, tag_diff, params, check_mode):
    if check_mode:
        return True, None, None

    before = ec2_subnet_utils.result_from_resource(subnet)

    if 'auto_assign_ip' in diff:
        subnet.meta.client.modify_subnet_attribute(
            SubnetId=subnet.id,
            MapPublicIpOnLaunch=dict(
                Value=diff['auto_assign_ip']['after']
            ),
        )
    if tag_diff:
        tags_to_update, tags_to_remove = tag_utils.from_diff(
            tag_diff, clear_existing=params['clear_tags']
        )
        if tags_to_update or tags_to_remove:
            tag_utils.update_resource(subnet, tags_to_update, tags_to_remove)

    subnet.reload()
    return True, subnet, dict(
        before=before,
        after=ec2_subnet_utils.result_from_resource(subnet)
    )


def validate_identification_params(params):
    if not params['id'] and not params['cidr']:
        raise errors.ValidationError(
            "Missing required parameters: subnet 'id' or 'cidr'"
        )


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            spec.params('auth', 'availability_zone',
                        'state', 'id', 'name', 'tags', 'clear_tags'),
            vpc=dict(),
            cidr=dict(),
            auto_assign_ip=dict(
                type='bool',
                default=False,
            ),
        ),
    )

    try:
        validate_identification_params(module.params)
        ec2 = boto.ec2_resource(module.params['auth'])

        if module.params['state'] == 'present':
            changed, subnet, diff = handle_present(ec2, module.params, module.check_mode)
        else:
            changed, subnet, diff = handle_absent(ec2, module.params, module.check_mode)

        if subnet is None:
            result = None
        else:
            result = ec2_subnet_utils.result_from_resource(subnet)
    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=changed, object=result, diff=diff)


if __name__ == "__main__":
    main()
