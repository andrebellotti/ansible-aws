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
module: ec2_vpc_address

author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)

short_description: Manage EC2 VPC addresses

description:
  -  Allocate, associate or release an AWS EC2 VPC address (Elastic IP).

extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.tags
  - steampunk.aws.clear_tags

options:
  state:
    description:
      - The desired state of the VPC address.
      - I(state) C(associated) if not already, it will allocate address, and
        associated it with instance or network interface.
      - If I(state) is C(allocated), the VPC address will be allocated or
        if already associated with an instance it will be disassociated, but
        not released.
      - If I(state) is C(absent), the VPC address will be automatically
        disassociated from the network interface or instance, if necessary.
    type: str
    choices: [ associated, allocated, absent ]
    default: associated
  network_interface:
    description:
      - ID of the network interface to associate the VPC address with.
      - VPC address will be associated with the primary private IP
        of the specified network interface.
      - The value of this parameter is only relevant when I(state) is
        C(associated).
      - Exactly one of I(network_interface), I(instance) is required.
      - When updating an existing VPC address that is already associated,
        the module will perform re-association.
    type: str
  instance:
    description:
      - ID of the instance whose primary network interface the VPC
        address will be associated with.
      - The value of this parameter is only relevant when I(state) is
        C(associated).
      - Exactly one of I(instance), I(network_interface) is required.
      - When updating an existing VPC address that is already associated,
        the module will perform re-association.
    type: str
  ip:
    description:
      - The public (Elastic) IP address.
      - You can use this parameter to uniquely identify the VPC address.
      - If I(state) is C(present) and the VPC address with the specified
        public IP does not exist, the module will attempt to reclaim the
        specified public IP.
    type: str
seealso:
  - module: ec2_vpc_address_info
"""

EXAMPLES = """
- name: Allocate a new VPC address without associating it
  ec2_vpc_address:
    state: allocated
  register: first_address

- name: Associate a previously allocated VPC address with a network interface
  ec2_vpc_address:
    ip: "{{ first_address.object.ip }}"
    network_interface: eni-0206c72e4ee240662
  register: first_address_associated

- name: Dissociate a VPC address
  ec2_vpc_address:
    ip: "{{ first_address_associated.object.ip }}"
    state: allocated
  register: first_address_dissociated

- name: Release a VPC address
  ec2_vpc_address:
    ip: "{{ first_address_dissociated.object.ip }}"
    state: absent

- name: Try to reclaim a previously released VPC address
  ec2_vpc_address:
    ip: "{{ first_address.object.ip }}"
    network_interface: eni-0206c72e4ee240662
  register: reclaimed_address

- name: Allocate & associate a new VPC address with a network interface
  ec2_vpc_address:
    network_interface: eni-04f3354b9b75ec51d
  register: another_address

- name: Re-associate an existing VPC address with the primary
        network interface of an instance
  vpc_address:
    ip: "{{ another_address.object.ip }}"
    instance: i-0c79884ded545df1a

- name: Release an associated VPC address
  ec2_vpc_address:
    ip: "{{ another_address.object.ip }}"
    state: absent
"""

RETURN = """
object:
  description:
    - An object representing an EC2 VPC address.
  type: complex
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
      description: Tags associated with the VPC address.
      type: dict
      returned: always
      sample: {'Name': 'my-vpc-address'}
  returned: success and I(state=present)
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, errors, tag_utils
)


def allocate_address(ec2, ip, domain='vpc'):
    # Pass in domain parameter, aldough default is set to "vpc", optional could be "standard".
    args = dict(Address=ip) if ip else {}
    return ec2.VpcAddress(ec2.meta.client.allocate_address(
        Domain=domain, **args)['AllocationId']
    )


def disassociate_address(elastic_instance):
    elastic_instance.meta.client.disassociate_address(
        AssociationId=elastic_instance.association_id
    )
    elastic_instance.load()


def find_vpc_address(ec2, ip_address):
    if not ip_address:
        return None

    try:
        addr = ec2.meta.client.describe_addresses(PublicIps=[ip_address])
        return ec2.VpcAddress(addr['Addresses'][0]['AllocationId'])
    except boto.ClientError as e:
        if e.operation_name != "DescribeAddresses":
            raise
        return None


def create_result(params, elastic_instance):
    result = dict(
        ip=params['ip'] if params['ip'] else elastic_instance.public_ip,
        allocation_id=elastic_instance.allocation_id,
        network_interface=params['network_interface'],
        instance=params['instance'],
        tags=params['tags'],
    )

    return result


def update_tags(elastic_instance, tags):
    tags_to_update = tag_utils.to_boto3(tags)
    elastic_instance.meta.client.create_tags(
        Resources=[
            elastic_instance.allocation_id
        ],
        Tags=tags_to_update
    )


def ensure_allocated(ec2, params, check_mode):
    elastic_instance = find_vpc_address(ec2, params['ip'])

    # Allocate new address
    if not elastic_instance:
        if not check_mode:
            elastic_instance = allocate_address(ec2, params['ip'])
            update_tags(elastic_instance, params['tags'])
        return True, create_result(params, elastic_instance)

    # Disassociate
    if elastic_instance.association_id:
        if not check_mode:
            disassociate_address(elastic_instance)
        return True, create_result(params, elastic_instance)

    return False, create_result(params, elastic_instance)


def ensure_associated(ec2, params, check_mode):
    elastic_instance = find_vpc_address(ec2, params['ip'])

    # Allocate new address
    if not elastic_instance:
        if check_mode:
            return True, create_result(params, elastic_instance)
        elastic_instance = allocate_address(ec2, params['ip'])
        update_tags(elastic_instance, params['tags'])

    # Associate address
    if params['instance'] and elastic_instance.instance_id != params['instance']:
        if not check_mode:
            elastic_instance.associate(InstanceId=params['instance'])
        return True, create_result(params, elastic_instance)

    if (
        params['network_interface'] and
        elastic_instance.network_interface_id != params['network_interface']
    ):
        if not check_mode:
            elastic_instance.associate(NetworkInterfaceId=params['network_interface'])
        return True, create_result(params, elastic_instance)

    return False, create_result(params, elastic_instance)


def ensure_absent(ec2, params, check_mode):
    # Release Elastic IP
    elastic_instance = find_vpc_address(ec2, params['ip'])

    if not elastic_instance:
        return False, None

    if not check_mode:
        elastic_instance.release()

    return True, None


def validate_identification_params(params):
    if params['state'] == 'associated' and not(params['instance'] or params['network_interface']):
        raise errors.ValidationError(
            "Missing required parameters: 'instance' or 'network_interface'"
        )

    if params['state'] == 'absent' and not params['ip']:
        raise errors.ValidationError(
            "Missing required parameters: 'ip' to release"
        )


def main():
    module_args = dict(
        spec.params('auth', 'tags', 'clear_tags', service='ec2'),
        state=dict(
            type='str',
            choices=['associated', 'allocated', 'absent'],
            default='associated',
        ),
        network_interface=dict(
            type='str',
        ),
        instance=dict(
            type='str',
        ),
        ip=dict(
            type='str',
        ),
    )

    module = AnsibleModule(argument_spec=module_args,
                           supports_check_mode=True)

    try:
        validate_identification_params(module.params)
        ec2 = boto.ec2_resource(module.params['auth'])

        if module.params['state'] == 'associated':
            changed, address = ensure_associated(ec2, module.params, module.check_mode)

        elif module.params['state'] == 'allocated':
            changed, address = ensure_allocated(ec2, module.params, module.check_mode)

        else:
            changed, address = ensure_absent(ec2, module.params, module.check_mode)

        module.exit_json(changed=changed, object=address)

    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
