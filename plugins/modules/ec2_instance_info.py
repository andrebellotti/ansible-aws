#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>


from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "XLAB Steampunk",
}

DOCUMENTATION = """
module: ec2_instance_info
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: List EC2 instances
description:
  - Retrieve information about AWS EC2 instances.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.ids
  - steampunk.aws.names
  - steampunk.aws.filters
options:
  states:
    description:
      - Limit the results to EC2 instances in the specified states.
      - By default, the module includes instances in all states except
        C(terminated).
      - This parameter cannot contain C(terminated), as terminated instances
        are treated as absent.
    type: list
    default: [pending, running, stopping, stopped, shutting-down]
  ami:
    description: ID of the AMI used to launched the instance
    type: str
  type:
    description: Type of the EC2 instance.
    type: str
  subnet:
    description: ID of the subnet where the instance is running.
    type: str
seealso:
  - module: ec2_instance
"""

EXAMPLES = """
- name: List all EC2 instances
  ec2_instance_info:
  register: result

- name: List a specific EC2 instance
  ec2_instance_info:
    ids: i-0c79884ded545df1a
  register: result

- name: List several EC2 instances according to their name tag
  ec2_instance_info:
    names:
      - app-server
      - db-server
  register: result
"""

RETURN = """
object:
    description:
      - An object representing the EC2 Instance.
    type: complex
    contains:
      id:
        description: ID of the EC2 instance.
        returned: always
        type: str
        sample: i-841b9271gd
      launched_at:
        description: The time when instance was launched.
        returned: always
        type: str
        sample: 2020-04-15T08:08:40+00:00
      type:
        description: EC2 instance type.
        returned: always
        type: str
        sample: a1.xsmall
      ami:
        description: ID of the AMI used to launched the instance.
        returned: always
        type: str
        sample: ami-0343ab73df9eb1496
      vpc:
        description: ID of the VPC containing the instance.
        returned: always
        type: str
        sample: vpc-129385ns2s2
      subnet:
        description: ID of the subnet containing the instance.
        returned: always
        type: str
        sample: subnet-14hs85ns83hg
      availability_zone:
        description: ID of the availability zone for the instance.
        returned: always
        type: str
        sample: az-use-1
      security_groups:
        description: IDs of security groups associated with the instance.
        returned: always
        type: list
        sample: [ sg-27fhs72gs922f ]
      network_interface:
        description: ID of the instance's primary network interface.
        returned: always
        type: str
        sample: eni-2dfr38df335
      secondary_network_interfaces:
        description: IDs of the secondary network interfaces attached to the instance.
        returned: always
        type: list
        sample: []
      key_pair:
        description: Name of the key pair to be used when connecting
          to the instance.
        type: str
        returned: always
        sample: my-key-pair
      tenancy:
        description: The instance tenancy setting.
        type: str
        returned: always
        sample: default
      monitoring:
        description: CloudWatch monitoring mode for the instance.
        type: str
        returned: always
        sample: detailed
      on_instance_initiated_shutdown:
        description: The behavior when shut down is initiated from the instance.
        type: str
        returned: always
        sample: terminate
      state:
        description: State of the EC2 instance as reported by AWS.
        type: str
        returned: always
        sample: running
    returned: success
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, errors, ec2_instance_utils, ec2_filters,
)


def validate_states(states):
    if 'terminated' in states:
        raise errors.ValidationError(
            "State parameter cannot contain 'terminated'"
        )


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            spec.params('auth', 'ids', 'names', 'filters'),
            states=dict(
                type='list',
                default=['pending', 'running', 'stopping', 'stopped', 'shutting-down'],
            ),
            ami=dict(),
            type=dict(),
            subnet=dict(),
        ),
    )

    filter_mapping = dict(
        ec2_filters.mapping_for_params('names'),
        ids='instance-id',
        states='instance-state-name',
        ami='image-id',
        type='instance-type',
        subnet='subnet-id',
    )

    try:
        validate_states(module.params['states'])

        ec2 = boto.ec2_resource(module.params['auth'])
        filters = ec2_filters.build_from_mapping(filter_mapping, module.params)

        instances = []
        for instance in ec2.instances.filter(Filters=filters):
            instances.append(
                ec2_instance_utils.result_from_remote(instance)
            )
    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=instances)


if __name__ == "__main__":
    main()
