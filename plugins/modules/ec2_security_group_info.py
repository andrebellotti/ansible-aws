#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
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
module: ec2_security_group_info
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: List EC2 VPC security groups.
description:
  - Retrieve information about AWS EC2 VPC security groups.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.filters
options:
  names:
    description:
      - The names of the security groups to retrieve.
        The default is to retrieve all security groups.
    default: []
    required: false
    type: list
  ids:
    description:
      - The IDs of the security groups to retrieve.
        The default is to retrieve all security groups.
    default: []
    required: false
    type: list
  vpc:
    description:
      - ID of the VPC.
      - May be used to limit the results to security groups in the given VPC only.
    type: str
seealso:
  - module: ec2_security_group
"""

# language=yaml
EXAMPLES = """
- name: List all security groups
  ec2_security_group_info:
  register: result

- name: Get information for a specific security group by name
  ec2_security_group_info:
    names: my-first-security-group
  register: result

- name: List information for multiple security groups by their IDs
  ec2_security_group_info:
    ids:
      - sg-1a2b3cd
      - sg-feda903
  register: result

- name: Use a complex filter for security groups
  ec2_security_group_info:
    vpc: vpc-182ffaed83
    filters:
      ip-permission.cidr: 198.51.100.64/25
  register: result
"""

# language=yaml
RETURN = """
objects:
  description: A list of EC2 VPC security groups.
  returned: success
  type: list
  contains:
    id:
      description: The ID of the security group.
      type: str
      returned: always
    name:
      description: The name of the security group.
      type: str
      returned: always
    vpc:
      description: The ID of the VPC this security group is assigned to.
      type: str
      returned: always
    description:
      description: The security group's description.
      type: str
      returned: always
    tags:
      description: The tags assigned to this security group.
      type: dict
      returned: always
    ingress:
      description: Ingress (inbound) security rules.
      type: dict
      returned: always
      contains:
        rules:
          description:
            - Ingress (inbound) security rules.
            - Rules are normalized so each rule only contains one of I(security_groups) or
              I(ip_ranges), and at most one element.
          type: list
          returned: always
          contains: &gress_suboptions
            protocol:
              description: The protocol this rule applies to.
              type: str
              returned: always
            port_from:
              description: The start port (inclusive) of the port range of this rule.
              type: int
              returned: when I(protocol=[tcp, udp])
            port_to:
              description: The start port (inclusive) of the port range of this rule.
              type: int
              returned: when I(protocol=[tcp, udp])
            icmp_type:
              description: The ICMP type for this rule.
              type: int
              returned: when I(protocol=[icmp, icmpv6])
            icmp_code:
              description: The ICMP code (subtype) for this rule.
              type: int
              returned: when I(protocol=[icmp, icmpv6])
            security_groups:
              description: A list of a single security group ID and its description.
              type: list
              returned: when I(ip_range) is not present
              contains:
                id:
                  description: The ID of the security group this rule references.
                  type: str
                  returned: always
                description:
                  description: The description for this security group reference, if any.
                  type: str
            ip_ranges:
              description: A list of a single IP range for this rule in CIDR notation.
              type: list
              returned: when I(security_group) is not present
              contains:
                cidr:
                  description: In CIDR notation, the IP range of this rule.
                  returned: always
                  type: str
                description:
                  description: An optional description for this IP range.
                  type: str
    egress:
      description: Egress (outbound) security rules.
      type: dict
      returned: always
      contains:
        rules:
          description:
            - Egress (outbound) security rules.
            - Rules are normalized so each rule only contains one of I(security_groups) or
              I(ip_ranges), and at most one element.
          type: list
          returned: always
          contains: *gress_suboptions
  sample:
    objects:
      - id: sg-df1b2aa66
        name: my-first-secgroup
        vpc: vpc-faff5721
        description: A description for my first security group.
        tags:
          MyCompany-Department: legal
        ingress:
          rules:
            - protocol: tcp
              port_from: 22
              port_to: 22
              ip_ranges:
                - cidr: 0.0.0.0/0
                  description: the world
        egress:
          rules:
            - protocol: icmp
              icmp_type: 8
              icmp_code: 0
              security_groups:
                - id: sg-64508346
                  description: local sonar
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.steampunk.aws.plugins.module_utils import spec, boto, ec2_filters, errors
from ansible_collections.steampunk.aws.plugins.module_utils.ec2_security_group_utils import \
    boto_dict_to_module_return


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            vpc=dict(),
            **spec.params("names", "ids", "auth", "filters")
        )
    )

    module_filter_mapping = {
        "names": "group-name",
        "ids": "group-id",
        "vpc": "vpc-id"
    }

    secgroups = []
    try:
        ec2 = boto.ec2_resource(module.params['auth'])
        filters = ec2_filters.build_from_mapping(module_filter_mapping, module.params)
        secgroups = [boto_dict_to_module_return(sg.meta.data)
                     for sg in ec2.security_groups.filter(Filters=filters)]
    except errors.AwsCollectionError as e:
        module.fail_json(msg="{0}: {1}".format(type(e), str(e)))
    module.exit_json(changed=False, objects=secgroups)


if __name__ == "__main__":
    main()
