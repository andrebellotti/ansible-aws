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
module: ec2_subnet_info
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: List EC2 VPCs
description:
  -  Retrieve information about AWS EC2 Virtual Private Clouds.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.ids
  - steampunk.aws.names
  - steampunk.aws.filters
options:
  vpc:
    description:
      - ID of the VPC.
      - May be used to limit the results to subnets in the given VPC only.
    type: str
seealso:
  - module: ec2_subnet
"""

# language=yaml
EXAMPLES = """
- name: List subnets across all VPCs in the selected region
  ec2_subnet_info:
  register: result

- name: List subnets in a specific VPC
  ec2_subnet_info:
    vpc: vpc-2s3726csbs3
    ids: subnet-s9324d4da4
  register: result

- name: List several subnets by name
  ec2_subnet_info:
    names:
      - my-subnet-1
      - my-subnet-2
  register: result

- name: List all available subnets
  ec2_subnet_info:
    filters:
      state: available
  register: result
"""

# language=yaml
RETURN = """
objects:
  description:
    - A list of objects representing EC2 subnets.
  type: list
  returned: success
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
    objects:
      - id: subnet-123456
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
    spec, boto, ec2_filters, errors, ec2_subnet_utils
)


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            spec.params('auth', 'ids', 'names', 'filters'),
            vpc=dict(),
        ),
    )

    filter_mapping = dict(
        ec2_filters.mapping_for_params('names'),
        ids='subnet-id',
        vpc='vpc-id',
    )

    try:
        ec2 = boto.ec2_resource(module.params['auth'])
        filters = ec2_filters.build_from_mapping(filter_mapping, module.params)
        subnets = [ec2_subnet_utils.result_from_resource(subnet)
                   for subnet in ec2.subnets.filter(Filters=filters)]
    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e), exception=e)

    module.exit_json(changed=False, objects=subnets)


if __name__ == "__main__":
    main()
