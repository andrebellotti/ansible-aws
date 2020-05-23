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
module: ec2_vpc
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: Manage EC2 VPCs
description:
  -  Create, update or delete an AWS EC2 Virtual Private Cloud.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.state
  - steampunk.aws.id
  - steampunk.aws.tags
  - steampunk.aws.clear_tags
options:
  name:
    description:
      - Name of the VPC.
      - This parameter is required unless I(id) is provided.
      - The value of this parameter will be used together with
        the value of I(cidr) to uniquely identify the VPC.
    type: str
  cidr:
    description:
      - IPv4 network range to assign to the VPC, in CIDR notation.
      - This parameter is required unless I(id) is provided.
      - In the absence of I(id), the value of this parameter will be
        used together with the value of I(name) to uniquely identify the VPC.
    type: str
  instance_tenancy:
    description:
      - Allowed tenancy for EC2 instances launched into the VPC.
      - Once a VPC is created with C(dedicated) tenancy, you may update
        the parameter to C(default), but not vice versa. Note that the
        the change will take effect for newly launched instances only.
    choices: [default, dedicated]
    type: str
seealso:
  - module: ec2_vpc_info
"""

# language=yaml
EXAMPLES = """
- name: Create a VPC
  ec2_vpc:
    name: my-vpc
    cidr: 10.0.0.0/16
    instance_tenancy: dedicated
  register: result

- name: Update VPC's instance tenancy
  ec2_vpc:
    id: "{{ result.object.id }}"
    instance_tenancy: default

- name: Clear all VPC's tags
  ec2_vpc:
    id: "{{ result.object.id }}"
    clear_tags: true

- name: Delete a VPC
  ec2_vpc:
    id: "{{ result.object.id }}"
    state: absent
"""

# language=yaml
RETURN = """
object:
  description:
    - An object representing an EC2 VPC.
  type: dict
  returned: success and I(state=present)
  contains:
    id:
      description: The ID of the VPC.
      type: str
      returned: always
    cidr:
      description: The CIDR block for the VPC.
      type: str
      returned: always
    instance_tenancy:
      description: The instance tenancy setting for instances launched in the VPC.
      type: str
      returned: always
    tags:
      description: The tags assigned to the VPC.
      type: dict
      returned: always
  sample:
    object:
      id: vpc-123456
      cidr: 10.0.0.0/16
      instance_tenancy: dedicated
      tags:
        bu: finance
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, tag_utils, ec2_filters, errors, validation, ec2_vpc_utils
)


def _identify_vpc(ec2, params, fail_nonexisting_id=False):
    if params["id"]:
        vpc = ec2_vpc_utils.get_vpc_by_id(ec2, params["id"], fail_nonexisting_id)
        # currently we do not fallback to (name, cidr) identification
        # if identification by ID fails.
        if not vpc and fail_nonexisting_id:
            raise errors.ObjectDoesNotExist("VPC with id {0} does not exist".format(params["id"]))
        return vpc
    return _get_vpc_by_primary_cidr_and_name(ec2, params["name"], params["cidr"])


def _get_vpc_by_primary_cidr_and_name(ec2, name, cidr):
    vpc_collection = ec2.vpcs.filter(
        Filters=ec2_filters.from_dict({
            'cidr': cidr,
            'tag:Name': name,
        }))
    vpcs = list(vpc_collection)

    # It can happen that we have multiple VPCs with identical CIDR
    # and name tags on AWS
    if len(vpcs) > 1:
        raise errors.AmbiguousObjectError("Duplicate VPCs exist ({0}), could not reliably "
                                          "determine the correct one.".format(vpcs))
    if not vpcs:
        return None
    return vpcs[0]


def vpcs_diff(params, remote):
    """
    Calculates the diff based on the desired (supported) parameters
    and the current state of the remote object. Returns diff for every
    attribute that the module will potentially alter.

    :param params:
    :param remote:
    :return: dict of the form  {
        'attr1': {'before':'a', 'after':'b'},
        'attr2': { ... }
    }
    """
    diff = {}

    if params['cidr'] and remote.cidr_block != params['cidr']:
        diff['CidrBlock'] = dict(
            before=remote.cidr_block,
            after=params['cidr'],
        )
    tenancy = params['instance_tenancy']  # None if param was omitted
    if tenancy and remote.instance_tenancy != tenancy:
        diff['InstanceTenancy'] = dict(
            before=remote.instance_tenancy,
            after=params['instance_tenancy']
        )
    return diff


def update(vpc, diff, tag_diff, params, check_mode):
    if check_mode:
        return True, None, diff

    vpc_before_update = vpc.meta.data.copy()

    if 'InstanceTenancy' in diff:
        requested_tenancy = diff['InstanceTenancy']['after']
        if requested_tenancy != 'default':
            raise errors.ValidationError("instance_tenancy can only be changed to 'default'")
        vpc.meta.client.modify_vpc_tenancy(
            VpcId=vpc.id,
            InstanceTenancy=requested_tenancy,
        )
    if tag_diff:
        tags_to_update, tags_to_remove = tag_utils.from_diff(
            tag_diff, clear_existing=params['clear_tags']
        )
        if tags_to_update or tags_to_remove:
            tag_utils.update_resource(vpc, tags_to_update, tags_to_remove)

    vpc.reload()
    return True, vpc, dict(
        before=vpc_before_update,
        after=vpc.meta.data,
    )


def delete(vpc, check_mode):
    if not check_mode:
        vpc_before = vpc.meta.data
        vpc.delete()
        return True, None, dict(
            before=vpc_before,
            after=dict(),
        )
    return True, None, None


def create(resource, params, check_mode):
    if check_mode:
        return True, None, None

    payload = dict(
        CidrBlock=params['cidr'],
    )

    if params['instance_tenancy']:
        payload['InstanceTenancy'] = params['instance_tenancy']

    try:
        vpc = resource.create_vpc(**payload)
    except boto.ClientError as e:
        # this is documented as InvalidVpcRange, but boto has InvalidVpc.Range
        if e.response["Error"]["Code"] == "InvalidVpc.Range":
            raise errors.ValidationError("Invalid VPC range: The block range must be between a "
                                         "/28 netmask and /16 netmask.")
        raise
    # we cannot tag the vpc at the time of creation,
    # so we do it in a separate call
    vpc.create_tags(
        Tags=tag_utils.to_boto3(params['tags'], name=params['name']),
    )
    vpc.wait_until_available()

    # get the up-to-date representation with
    # correct state and name tag
    vpc.reload()
    return True, vpc, dict(
        before=dict(),
        after=vpc.meta.data,
    )


def sync(resource, state, params, check_mode):
    if state == 'absent':
        vpc = _identify_vpc(resource, params)
        if not vpc:  # trying to delete a non-existing vpc
            return False, None, None

        return delete(vpc, check_mode)

    else:
        vpc = _identify_vpc(resource, params, fail_nonexisting_id=True)
        if not vpc:  # we're creating a VPC
            return create(resource, params, check_mode)

        # we're trying to update an existing VPC
        # check if it needs updating at all
        diff = vpcs_diff(params, vpc)

        current_tags = tag_utils.from_boto3(vpc.tags)
        tag_diff = tag_utils.get_diff(params['name'], params['tags'], current_tags)
        tags_to_update, tags_to_remove = tag_utils.from_diff(
            tag_diff, clear_existing=params['clear_tags']
        )

        # they don't differ, do nothing
        if not (diff or tags_to_update or tags_to_remove):
            return False, vpc, None

        # validate and perform the update
        validation.validate_update(['CidrBlock'], diff)
        return update(vpc, diff, tag_diff, params, check_mode)


def validate_identification_params(params):
    if not params['id']:
        for param in ('name', 'cidr'):
            if not params[param]:
                return "You must specify 'name' and 'cidr'"
    return None


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            spec.params('auth', 'state', 'id', 'name',
                        'tags', 'clear_tags'),
            cidr=dict(),
            instance_tenancy=dict(
                # we are not setting a default value to prevent unwanted
                # updates in case the parameter is omitted
                choices=['default', 'dedicated'],
            ),
        ),
    )

    msg = validate_identification_params(module.params)
    if msg:
        module.fail_json(msg=msg)

    try:
        ec2 = boto.ec2_resource(module.params['auth'])
        changed, vpc, diff = sync(ec2, module.params['state'], module.params, module.check_mode)
        if vpc is None:
            result = None
        else:
            result = ec2_vpc_utils.result_from_resource(vpc)
    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=changed, diff=diff, object=result)


if __name__ == "__main__":
    main()
