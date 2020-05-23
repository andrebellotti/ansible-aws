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
module: ec2_internet_gateway_info
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: List EC2 Internet Gateways
description:
  -  Retrieve information about AWS EC2 Internet Gateways.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.ids
  - steampunk.aws.names
  - steampunk.aws.filters
options:
  vpc:
    description:
      - ID of the VPC to which the internet gateway is attached.
    type: str
seealso:
  - module: ec2_internet_gateway
"""

EXAMPLES = """
- name: List all internet gateways in the region
  ec2_internet_gateway_info:

- name: List only specific internet gateways
  ec2_internet_gateway_info:
    ids:
      - igw-13a244t23
      - igw-a862nf0sd

- name: List the internet gateway attached to a VPC
  ec2_internet_gateway_info:
    vpc: vpc-2jdb5kd83fs
"""

RETURN = """
objects:
  description:
    - A list of objects representing EC2 Internet Gateways.
  contains:
    id:
      description: ID of the internet gateway
      returned: always
      type: str
      sample: igw-841b9271gd
    vpc:
      description: ID of the VPC the internet gateway is attached
        to, or None.
      type: str
      returned: always
      sample: vpc-2w7hs924hs
    tags:
      description: Tags associated with the internet gateway.
      type: dict
      returned: always
      sample: {'environment': 'staging', 'Name': 'my-gateway'}
  returned: success
  type: list
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, ec2_filters, errors, ec2_internet_gateway_utils,
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
        ids='internet-gateway-id',
        vpc='attachment.vpc-id',
    )

    try:
        ec2 = boto.ec2_resource(module.params['auth'])
        filters = ec2_filters.build_from_mapping(filter_mapping, module.params)

        gateways = []
        for gateway in ec2.internet_gateways.filter(Filters=filters):
            gateways.append(
                ec2_internet_gateway_utils.result_from_remote(gateway)
            )

    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e), exception=e)

    module.exit_json(changed=False, objects=gateways)


if __name__ == "__main__":
    main()
