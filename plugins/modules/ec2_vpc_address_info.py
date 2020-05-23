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
module: ec2_vpc_address_info
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: List EC2 VPC addresses
description:
  -  Retrieve information about AWS EC2 VPC addresses.
extends_documentation_fragment:
  - steampunk.aws.auth
options:
  ips:
    description: Limit results to the specified VPC addresses only
    type: list
seealso:
  - module: ec2_vpc_address
"""

EXAMPLES = """
- name: List all VPC addresses in a region
  ec2_vpc_address_info:
  register: result

- name: List specific VPC addresses
  ec2_vpc_address_info:
    ips:
      - 3.21.120.93
      - 3.22.108.97
  register: result
"""

RETURN = """
objects:
  description:
    - A list of objects representing EC2 VPC addresses.
  contains:
    ip:
      description: The Elastic IP address.
      returned: always
      type: str
      sample: 3.20.251.70
    allocation_id:
      description: Allocation ID of the VPC address.
      returned: always
      type: str
      sample: eipalloc-04bed816a62ae64b1
    network_interface:
      description: ID of the network interface VPC address is associated with.
      returned: always
      type: str
      sample: eni-0a6d3406ea74e7bab
    instance:
      description: ID of the instance to which the network interface associated
        with the VPC address is attached (if any).
      returned: always
      type: str
      sample: i-0c79884ded545df1a, None
    tags:
      description: Tags associated with the internet gateway.
      type: dict
      returned: always
      sample: {'Name': 'my-vpc-address'}
  returned: success
  type: list
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, errors, tag_utils
)


def create_result(address):
    result = dict(
        ip=address.get('PublicIp'),
        allocation_id=address.get('AllocationId'),
        network_interface=address.get('NetworkInterfaceId'),
        instance=address.get('InstanceId'),
        tags=tag_utils.from_boto3(address['Tags']) if 'Tags' in address else None,
    )
    return result


def find_vpc_address(ec2, params):
    if not params['ips']:
        return ec2.meta.client.describe_addresses()['Addresses']

    try:
        return ec2.meta.client.describe_addresses(PublicIps=params['ips'])['Addresses']
    except boto.ClientError as e:
        if e.operation_name != "DescribeAddresses":
            raise
        return []


def main():
    module_args = dict(
        spec.params('auth', service='ec2'),
        ips=dict(
            type='list',
        ),
    )

    module = AnsibleModule(argument_spec=module_args,
                           supports_check_mode=True)

    try:
        ec2 = boto.ec2_resource(module.params['auth'])
        addresses = find_vpc_address(ec2, module.params)
        module.exit_json(changed=False, objects=[create_result(a) for a in addresses])

    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
