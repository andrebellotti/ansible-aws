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
module: ec2_network_interface_info
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: List EC2 Elastic Network Interfaces.
description:
  - Retrieve information about AWS EC2 Elastic Network Interfaces.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.ids
  - steampunk.aws.names
  - steampunk.aws.filters
options:
  subnet:
    description:
      - The ID of a subnet.
      - May be used to limit the results to network interfaces in the specified subnet.
    type: str
seealso:
  - module: ec2_network_interface
"""

# language=yaml
EXAMPLES = """
- name: List all network interfaces
  ec2_network_interface_info:
  register: result

- name: Get information for a specific network interface by name
  ec2_network_interface_info:
    names: my-first-network-interface
  register: result

- name: List information for multiple network interfaces by their IDs
  ec2_network_interface_info:
    ids:
      - eni-fce81a6
      - eni-47bga99
  register: result

- name: Use a complex filter for network interfaces
  ec2_network_interface_info:
    subnet: subnet-d56a1e85
    filters:
      association.public-ip: 192.0.2.59
  register: result
"""

# language=yaml
RETURN = """
objects:
  description:
    - A list of objects representing EC2 network interfaces.
  type: list
  returned: success
  contains:
    id:
      description: The ID of the network interface
      type: str
      returned: always
    description:
      description: The description of the network interface, if any.
      type: str
      returned: always
    subnet:
      description: The ID of the subnet this network interface is assigned to.
      type: str
      returned: always
    security_groups:
      description: The IDs of security groups assigned to this network interface. At least one.
      type: list
      elements: str
      returned: always
    type:
      description: The type of this network interface.
      type: str
      returned: always
    tags:
      description: The tags assigned to this network interface.
      type: dict
      returned: always
    mac_address:
      description: The MAC address of this network interface.
      type: str
      returned: always
    attachment:
      description: The attachment to an instance, if any.
      type: dict
      returned: when I(state=attached)
      contains:
        instance:
          description: The ID of the instance the network interface is attached to.
          type: str
          returned: always
        device_index:
          description: The hardware device index the network interface is attached to.
          type: str
          returned: always
        keep_on_termination:
          description: Whether the network interface is preserved when terminating the instance.
          type: str
          returned: always
    public_ip:
      description: The public IPv4 address or the VPC address (Elastic IP) associated with this
                   network interface, if any.
      type: str
      returned: always
    ip:
      description: The primary private IPv4 address assigned to this network interface.
      type: str
      returned: always
    source_dest_check:
      description: Whether source-destination checking is enabled for this network interface.
      type: bool
      returned: always
  sample:
    objects:
      - id: eni-ba546d69
        description: My First Elastic Network Interface.
        subnet: subnet-faff387
        security_groups:
          - sg-1
        type: normal
        tags:
          Name: myfirsteni
        mac_address: "00:05:B0:E9:E7:D0"
        attachment:
          instance: i-b856a2857fadfa
          device_index: 0
          keep_on_termination: false
        public_ip: null
        ip: 192.0.2.58
        source_dest_check: true
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.steampunk.aws.plugins.module_utils import \
    spec, boto, ec2_filters, errors
from ansible_collections.steampunk.aws.plugins.module_utils.ec2_network_interface_utils import \
    NetworkInterface


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            subnet=dict(),
            **spec.params("names", "ids", "auth", "filters")
        )
    )

    module_filter_mapping = dict(
        ec2_filters.mapping_for_params("names"),
        ids="network-interface-id",
        subnet="subnet-id"
    )

    result = []
    try:
        ec2 = boto.ec2_resource(module.params["auth"])
        filters = ec2_filters.build_from_mapping(module_filter_mapping, module.params)
        response = ec2.network_interfaces.filter(Filters=filters)
        entities_sorted = sorted([NetworkInterface.from_boto_dict(eni.meta.data)
                                  for eni in response])
        result = [eni.to_module_return() for eni in entities_sorted]
    except errors.AwsCollectionError as e:
        module.fail_json(msg="{0}: {1}".format(type(e), str(e)))
    module.exit_json(changed=False, objects=result)


if __name__ == "__main__":
    main()
