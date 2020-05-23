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
module: ec2_vpc_info
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
seealso:
  - module: ec2_vpc
"""

# language=yaml
EXAMPLES = """
- name: List all VPCs
  ec2_vpc_info:
  register: result

- name: List a specific VPC
  ec2_vpc_info:
    ids: instance-a-b-c
  register: result

- name: List several VPCs by name
  ec2_vpc_info:
    names:
      - my-vpc-name
      - my-other-vpc-name
  register: result

- name: List all available VPCs
  ec2_vpc_info:
    filters:
      state: available
  register: result
"""

# language=yaml
RETURN = """
objects:
  description:
    - A list of objects representing EC2 VPCs.
  type: list
  returned: success
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
    objects:
      - id: vpc-123456
        cidr: 10.0.0.0/16
        instance_tenancy: dedicated
        tags:
          bu: finance
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, ec2_filters, errors, ec2_vpc_utils
)


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            spec.params('auth', 'ids', 'names', 'filters'),
        ),
    )

    filter_mapping = dict(
        ec2_filters.mapping_for_params('names'),
        ids='vpc-id',
    )

    try:
        ec2 = boto.ec2_resource(module.params['auth'])
        filters = ec2_filters.build_from_mapping(filter_mapping, module.params)
        vpcs = [ec2_vpc_utils.result_from_resource(vpc)
                for vpc in ec2.vpcs.filter(Filters=filters)]
    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=vpcs)


if __name__ == "__main__":
    main()
