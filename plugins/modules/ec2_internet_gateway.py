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

DOCUMENTATION = """
module: ec2_internet_gateway
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: Manage EC2 Internet Gateways
description:
  -  Create, update or delete AWS EC2 Internet Gateway and its
     attachment to a VPC.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.id
  - steampunk.aws.tags
  - steampunk.aws.clear_tags
options:
  state:
    description:
      - The desired state of the internet gateway.
      - To create and attach an internet gateway to a VPC, or to attach an
        existing internet gateway to a VPC, use I(state) = C(attached).
      - To create an internet gateway without attaching it to a VPC,
        or to detach an existing internet gateway from a VPC, use
        I(state) = C(detached).
      - To remove the internet gateway, use C(absent). Note that if necessary,
        VPC will be detached prior to removing the internet gateway.
    type: str
    choices: [attached, detached, absent]
    default: attached
  name:
    description:
      - Name tag for the internet gateway.
      - This parameter is required when creating the internet gateway.
      - In the absence of I(id), the value of this parameter will be used
        to try to identify the internet gateway.
    type: str
  vpc:
    description:
      - ID of the VPC to attach the internet gateway to.
      - If the internet gateway is already attached to a VPC different to
        the one specified, the module will detach the gateway from the VPC
        and attach it to the specified one.
      - Required if I(state) is C(attached).
      - When I(state) is C(detached) or C(absent), the value of
        this parameter is ignored.
    type: str
seealso:
  - module: ec2_internet_gateway_info
"""

EXAMPLES = """
- name: Create a detached internet gateway
  ec2_internet_gateway:
    name: detached-gateway
    state: detached
  register: detached_gateway

- name: Attach a previously detached internet gateway to a VPC
  ec2_internet_gateway:
    id: "{{ detached_gateway.object.id }}"
    vpc: vpc-2w7hs924hss
  register: result

- name: Detach and delete an internet gateway
  ec2_internet_gateway:
    id: "{{ result.object.id }}"
    state: absent

- name: Create another internet gateway, this time with VPC attachment
  ec2_internet_gateway:
    name: attached-gateway
    vpc: vpc-2w7hs924hss
  register: attached_gateway

- name: Detach an internet gateway from a VPC
  ec2_internet_gateway:
    id: "{{ attached_gateway.object.id }}"
    state: detached
"""

RETURN = """
object:
  description:
    - An object representing an EC2 Internet Gateway.
  type: complex
  contains:
    id:
      description: ID of the internet gateway
      returned: always
      type: str
      sample: igw-841b9271gd
    vpc:
      description: ID of the VPC the internet gateway is attached
        to, None otherwise.
      type: str
      returned: always
      sample: vpc-2w7hs924hs
    tags:
      description: Tags associated with the internet gateway.
      type: dict
      returned: always
      sample: {'environment': 'staging', 'Name': 'my-gateway'}
  returned: success and I(state=attached) or I(state=detached)
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, tag_utils, ec2_filters, errors, diff_utils, ec2_vpc_utils,
    ec2_internet_gateway_utils,
)


def identify_internet_gateway(ec2, gateway_id, gateway_name, fail_nonexisting_id=False):
    if gateway_id:
        return get_internet_gateway_by_id(ec2, gateway_id, fail_nonexisting_id=fail_nonexisting_id)
    return get_internet_gateway_by_name(ec2, gateway_name)


def get_internet_gateway_by_id(ec2, gateway_id, fail_nonexisting_id=False):
    gateway = ec2.InternetGateway(gateway_id)
    if gateway not in ec2.internet_gateways.filter(
        Filters=ec2_filters.from_dict({
            'internet-gateway-id': gateway_id,
        })
    ):
        if fail_nonexisting_id:
            raise errors.ObjectDoesNotExist(
                'Internet gateway with id {0} does not exist.'.format(gateway_id)
            )
        return None

    gateway.load()

    return gateway


def get_internet_gateway_by_name(ec2, gateway_name):
    gateway_collection = ec2.internet_gateways.filter(
        Filters=ec2_filters.from_dict({
            'tag:Name': gateway_name,
        })
    )
    gateways = list(gateway_collection)

    if not gateways:
        return None

    if len(gateways) > 1:
        raise errors.AmbiguousObjectError(
            "More than one internet gateway named {0} exists".format(
                gateway_name
            )
        )
    gateway = gateways[0]
    gateway.load()

    return gateway


def gateways_diff(params, remote):
    diff = {}
    vpc = get_attached_vpc_id(remote)
    vpc_diff = diff_utils.attr_diff(params, 'vpc', vpc, report_none=True)
    if vpc_diff:
        diff['vpc'] = vpc_diff

    return diff


def check_update(gateway, params):
    """ Checks if update is necessary, and if it is,
        reports what needs to be updated.
    """
    diff = gateways_diff(params, gateway)

    current_tags = tag_utils.from_boto3(gateway.tags)
    tag_diff = tag_utils.get_diff(params['name'], params['tags'], current_tags)
    tags_to_update, tags_to_remove = tag_utils.from_diff(
        tag_diff, clear_existing=params['clear_tags']
    )

    # they don't differ, do nothing
    to_update = diff or tags_to_update or tags_to_remove

    return to_update, diff, tag_diff


def update_vpc_attachment(gateway, vpc_before_id, vpc_after_id):
    if vpc_before_id:
        gateway.detach_from_vpc(VpcId=vpc_before_id)
    if vpc_after_id:
        gateway.attach_to_vpc(VpcId=vpc_after_id)


def _validate_vpc_attachment(ec2, vpc_id):
    if vpc_id:
        ec2_vpc_utils.get_vpc_by_id(ec2, vpc_id, fail_nonexisting_id=True)


def update(ec2, gateway, gateway_diff, tag_diff, params, check_mode):
    diff = dict(
        before=ec2_internet_gateway_utils.result_from_remote(gateway),
    )

    if 'vpc' in gateway_diff:
        # we run this in advance to verify that the referenced vpc exists
        _validate_vpc_attachment(ec2, gateway_diff['vpc']['after'])

    if check_mode:
        result = ec2_internet_gateway_utils.result_from_params(
            gateway.id, params['vpc'], params['name'], params['tags']
        )
        diff['after'] = result
        return True, result, diff

    if 'vpc' in gateway_diff:
        update_vpc_attachment(
            gateway, gateway_diff['vpc']['before'], gateway_diff['vpc']['after']
        )

    if tag_diff:
        tags_to_update, tags_to_remove = tag_utils.from_diff(
            tag_diff, clear_existing=params['clear_tags']
        )
        if tags_to_update or tags_to_remove:
            tag_utils.update_resource(gateway, tags_to_update, tags_to_remove)

    gateway.reload()

    result = ec2_internet_gateway_utils.result_from_remote(gateway)
    diff['after'] = result
    return True, result, diff


def create(ec2, params, check_mode):
    diff = dict(
        before=dict(),
    )

    if params['state'] == 'attached':
        vpc = ec2_vpc_utils.get_vpc_by_id(ec2, params['vpc'], fail_nonexisting_id=True)

    if check_mode:
        result = ec2_internet_gateway_utils.result_from_params(
            'generated-by-aws', params['vpc'], params['name'], params['tags']
        )
        diff['after'] = result
        return True, result, diff

    gateway = ec2.create_internet_gateway()
    if params['state'] == 'attached':
        gateway.attach_to_vpc(VpcId=vpc.id)

    gateway.create_tags(
        Tags=tag_utils.to_boto3(params['tags'], name=params['name']),
    )
    gateway.reload()

    result = ec2_internet_gateway_utils.result_from_remote(gateway)
    diff['after'] = result
    return True, result, diff


def handle_present(ec2, params, check_mode):
    gateway = identify_internet_gateway(
        ec2, params['id'], params['name'], fail_nonexisting_id=True,
    )
    if not gateway:
        return create(ec2, params, check_mode)

    # see if we need to update
    to_update, diff, tag_diff = check_update(gateway, params)
    if not to_update:
        return False, ec2_internet_gateway_utils.result_from_remote(gateway), None
    return update(ec2, gateway, diff, tag_diff, params, check_mode)


def handle_absent(ec2, params, check_mode):
    gateway = identify_internet_gateway(ec2, params['id'], params['name'])
    if not gateway:  # trying to delete a non-existing gateway
        return False, None, None

    return delete(gateway, check_mode)


def get_attached_vpc_id(gateway):
    if not gateway.attachments:
        return None
    # boto3 returns attachments in a list, yet prohibits us from
    # attaching a gateway to more than one VPC. If we get more
    # than one attachment, something unexpected is happening.
    if len(gateway.attachments) > 1:
        raise errors.UnexpectedStateError(
            'More than one VPC attachment exists'
        )
    attachment = gateway.attachments[0]
    return attachment['VpcId']


def delete(gateway, check_mode):
    gateway_before = ec2_internet_gateway_utils.result_from_remote(gateway)
    diff = dict(
        before=gateway_before,
        after=dict(),
    )
    if check_mode:
        return True, None, diff

    if gateway_before['vpc']:
        gateway.detach_from_vpc(VpcId=gateway_before['vpc'])
    gateway.delete()

    return True, None, diff


def main():
    required_one_of = [
        ('id', 'name'),
    ]
    required_if = [
        ('state', 'attached', ['vpc']),
    ]

    module = AnsibleModule(
        supports_check_mode=True,
        required_if=required_if,
        required_one_of=required_one_of,
        argument_spec=dict(
            spec.params('auth', 'id', 'name',
                        'tags', 'clear_tags'),
            state=dict(
                choices=['attached', 'detached', 'absent'],
                default='attached',
            ),
            vpc=dict(),
        ),
    )

    try:
        ec2 = boto.ec2_resource(module.params['auth'])

        # what is typically present state encapsulates two states
        # in our case - attached and detached
        if module.params['state'] in ('attached', 'detached'):
            changed, gateway, diff = handle_present(
                ec2, module.params, module.check_mode
            )
        else:
            changed, gateway, diff = handle_absent(
                ec2, module.params, module.check_mode
            )
    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=changed, object=gateway, diff=diff)


if __name__ == "__main__":
    main()
