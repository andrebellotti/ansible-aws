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
module: ec2_network_interface
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: Manage EC2 Elastic Network Interfaces
description:
  -  Create, update or delete an AWS EC2 Elastic Network Interface.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.tags
  - steampunk.aws.clear_tags
options:
  id:
    description:
      - ID of the resource to perform the task on.
      - If specified, this parameter is used to identify the resource.
      - If omitted, a combination of I(subnet), I(ip), I(name), I(attachment.instance),
        I(attachment.device_index) is used to identify an existing instance, if possible.
    type: str
  name:
    description:
      - The name tag of the network interface.
      - Required for the creation of the network interface.
    type: str
  description:
    description:
       - An optional description of the network interface.
    type: str
  subnet:
    description:
      - The ID of the subnet in which to create the network interface.
      - Required when creating the network interface.
      - When I(id) is not present, it is used in combination with I(ip)
        to attempt to identify the network interface.
    type: str
  ip:
    description:
      - The primary private IPv4 addresses for the network interface.
      - If provided, must be within the IP range of I(subnet).
      - When I(id) is not present, it is used in combination with I(subnet) to attempt to identify
        the network interface.
      - If this parameter is omitted, the private IPv4 address will be selected
        by AWS from the pool of available private IPv4 addresses from the subnet specified by the
        I(subnet) parameter.
    type: str
  security_groups:
    description:
      - List of security group IDs to attach the network interface to.
      - Security groups must reside in the same VPC as I(subnet).
      - If the parameter is provided, at least one security group must be specified.
      - Required if I(clear_security_groups) is C(true).
      - If this parameter is omitted, the module will assume the default security group of the VPC
        in which the network interface exists.
    type: list
  clear_security_groups:
    description:
      - Whether security groups not listed in I(security_groups) should
        be removed from the network interface.
      - This parameter requires I(security_groups).
    type: bool
    default: false
  state:
    description:
      - The desired state of the network interface.
    type: str
    choices: [attached, detached, absent]
    default: attached
  source_dest_check:
    description:
      - Whether to enable or disable source/destination checking for the network interface.
      - This must be set to C(false) for interfaces used for NAT.
    type: bool
  type:
    description:
      - Type of the network interface.
      - Set this parameter to C(efa) to create an Elastic Fabric Adapter
        instead of a regular network interface.
    type: str
    choices: [normal, efa]
    default: normal
  attachment:
    description:
      - The configuration for an attachment of the network interface to an instance.
      - Required if I(state) is C(attached).
    type: dict
    suboptions:
      instance:
        description:
          - The ID of the instance to attach the network interface to.
        required: true
        type: str
      device_index:
        description:
          - Attach the network interface to the instance at this index.
          - If this parameter is omitted, the first available device index is used.
        type: int
      keep_on_termination:
        description:
          - Whether the network interface should be present after the
            instance it is attached to is terminated.
        type: bool
seealso:
  - module: ec2_network_interface_info
"""

# language=yaml
EXAMPLES = """
- name: Create a network interface in the default security group with an IP chosen by AWS
  ec2_network_interface:
    name: my-first-eni
    subnet: subnet-de593ab
    state: detached

- name: Create another network interface with custom settings and security groups
  ec2_network_interface:
    name: my-complicated-eni
    subnet: subnet-5ace7221
    ip: 192.0.2.158
    source_dest_check: false
    security_groups:
      - sg-06aa1300c4efeb57
      - sg-0b6f07cf42aasbde
    state: detached

- name: Create a network interface and attach it to an instance
  ec2_network_interface:
    name: my-attached-eni
    subnet: subnet-5afe1227
    ip: 198.51.100.85
    attachment:
      instance: i-18fg46a2dsd
      device_index: 5
      keep_on_termination: false
  register: attached_interface

- name: Detach a network interface from the instance
  ec2_network_interface:
    id: "{{ attached_interface.object.id }}"
    state: detached

- name: Modify a network interface's security groups
  ec2_network_interface:
    id: "{{ attached_interface.object.id }}"
    clear_security_groups: true
    security_groups:
      - sg-293474das3
    state: detached

- name: Remove a network interface
  ec2_network_interface:
    id: "{{ attached_interface.object.id }}"
    state: absent
"""

# language=yaml
RETURN = """
object:
  description:
    - A representation of the EC2 network interface.
  type: dict
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
    object:
      id: eni-ba546d69
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

from ansible.module_utils import six
from ansible.module_utils.compat import ipaddress
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, ec2_filters, errors, tag_utils, ec2_subnet_utils, ec2_security_group_utils,
    ec2_instance_utils
)
from ansible_collections.steampunk.aws.plugins.module_utils.entity_utils import ModuleEntityUnit
from ansible_collections.steampunk.aws.plugins.module_utils.ec2_network_interface_utils import \
    NetworkInterface, Attachment, get_network_interface_by_id
from ansible_collections.steampunk.aws.plugins.module_utils.ec2_security_group_utils import \
    security_group_exists, security_group_in_vpc


def identify_existing_eni(ec2, params_entity):
    """
    Identification logic, in order:
      - if an ID exists, use (unique = id)
      - if both subnet and IP exist, use (unique = subnet + ip)
      - if subnet exists, but IP doesn't exist:
          - if name and attachment are set, use (subnet + name + attachment (+branch to #1))
          - if name is set, but attachment isn't, use (nonunique = subnet + name)
          - if name is not set, but attachment is set, use (subnet + attachment (+branch to #1))
    #1
      - if device_index is set, use (unique = instance + device_index)
      - if device_index is not set, use (nonunique = instance)

    :type params_entity: NetworkInterface
    """
    if params_entity.eni_id is not None:
        return get_network_interface_by_id(ec2, params_entity.eni_id, fail_nonexisting_id=True)

    filters = {}
    if params_entity.subnet_id is not None:
        if params_entity.private_ip_primary is not None:
            filters["subnet-id"] = params_entity.subnet_id
            filters["addresses.private-ip-address"] = params_entity.private_ip_primary
            filters["addresses.primary"] = "true"
        else:
            if params_entity.tags is not None and params_entity.tags.get("Name") is not None:
                filters["subnet-id"] = params_entity.subnet_id
                filters["tag:Name"] = params_entity.tags["Name"]
            if params_entity.attachment is not None:
                filters["subnet-id"] = params_entity.subnet_id
                filters["attachment.instance-id"] = params_entity.attachment.instance_id
                if params_entity.attachment.device_index is not None:
                    filters["attachment.device-index"] = params_entity.attachment.device_index

    if not filters:
        return None
    all_enis = list(ec2.network_interfaces.filter(Filters=ec2_filters.from_dict(filters)))

    if len(all_enis) == 0:
        return None
    elif len(all_enis) == 1:
        all_enis[0].load()
        return all_enis[0]
    raise errors.UnexpectedStateError(
        "More than one network interface exists matching the task's identifying arguments."
    )


def validate_security_group(ec2, secgroup_id, vpc_id):
    if not security_group_exists(ec2, secgroup_id):
        raise errors.ObjectDoesNotExist("Security group does not exist: {0}".format(secgroup_id))

    if not security_group_in_vpc(ec2, secgroup_id, vpc_id):
        raise errors.ValidationError("Security group {0} is not in VPC {1}.".format(
            secgroup_id, vpc_id
        ))


def validate_ip_in_cidr(ip, cidr):
    address = ipaddress.ip_address(six.u(ip))
    network = ipaddress.ip_network(six.u(cidr), strict=False)
    if address not in network:
        raise errors.ValidationError("IP {0} not in subnet CIDR {1}.".format(ip, cidr))


def create_new_eni(ec2, subnet, params_entity):
    # the name is a tag, but we still require it for creation and identification
    if params_entity.tags is None or "Name" not in params_entity.tags:
        raise errors.ValidationError("name is required when creating a network interface")

    optional_params = {}
    if params_entity.private_ip_primary:
        optional_params["PrivateIpAddress"] = params_entity.private_ip_primary
        validate_ip_in_cidr(optional_params["PrivateIpAddress"], subnet.cidr_block)
    if params_entity.description:
        optional_params["Description"] = params_entity.description

    if params_entity.security_groups:
        security_groups = params_entity.security_groups
        for sg in security_groups:
            validate_security_group(ec2, sg, subnet.vpc_id)
    else:
        default_sg = ec2_security_group_utils.get_default_security_group_for_vpc(ec2, subnet.vpc_id)
        security_groups = [default_sg.id]

    eni = subnet.create_network_interface(
        Groups=security_groups,
        InterfaceType=NetworkInterface.interface_type_internal_to_boto(params_entity.eni_type),
        **optional_params
    )

    waiter = subnet.meta.client.get_waiter("network_interface_available")
    waiter.wait(NetworkInterfaceIds=[eni.id])
    return eni


def get_first_available_device_index(instance):
    interfaces = instance.network_interfaces_attribute
    indices = [i["Attachment"]["DeviceIndex"] for i in interfaces]
    return max(indices) + 1


def apply_keep_on_termination_policy(eni, attachment_id, keep_on_termination):
    eni.modify_attribute(Attachment={
        "AttachmentId": attachment_id,
        "DeleteOnTermination": not keep_on_termination
    })


def detach_and_wait(eni):
    eni.detach()
    waiter = eni.meta.client.get_waiter("network_interface_available")
    waiter.wait(NetworkInterfaceIds=[eni.id], Filters=ec2_filters.from_dict({
        "status": "available"
    }))


def verify_attachment_possible(ec2, eni, attachment_after):
    instance = ec2_instance_utils.get_instance_by_id(
        ec2, attachment_after.instance_id,
        fail_nonexisting_id=True, fail_terminated=True
    )
    interfaces = instance.network_interfaces_attribute
    indices = [i["Attachment"]["DeviceIndex"] for i in interfaces]
    if attachment_after.device_index is not None and attachment_after.device_index in indices:
        raise errors.DisallowedOperationError("Device index {0} for instance {1} is already taken."
                                              .format(attachment_after.device_index,
                                                      attachment_after.instance_id))
    if eni.availability_zone != instance.placement["AvailabilityZone"]:
        raise errors.DisallowedOperationError("Cannot attach ENI to instance in different "
                                              "availability zone (eni: {0}, i: {1})."
                                              .format(eni.availability_zone,
                                                      instance.placement["AvailabilityZone"]))


def verify_detachment_possible(attachment_before):
    if attachment_before.device_index == 0:
        raise errors.ValidationError("Cannot detach interface at device index 0 from instance {0}."
                                     .format(attachment_before.instance_id))


def do_new_attachment(ec2, eni, attachment_after):
    instance = ec2_instance_utils.get_instance_by_id(
        ec2, attachment_after.instance_id,
        fail_nonexisting_id=True, fail_terminated=True
    )
    if attachment_after.device_index is None:
        device_index = get_first_available_device_index(instance)
    else:
        device_index = attachment_after.device_index

    try:
        id_dict = eni.attach(InstanceId=instance.id, DeviceIndex=device_index)
    except boto.ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidParameterValue":
            raise errors.ValidationError(
                "Invalid parameter value: {0}".format(e.response["Error"]["Message"])
            )
        elif code == "AttachmentLimitExceeded":
            raise errors.DisallowedOperationError(e.response["Error"]["Message"])
        raise
    kot = attachment_after.keep_on_termination
    if kot is None:
        kot = True
    apply_keep_on_termination_policy(eni, id_dict["AttachmentId"], kot)
    eni.load()


def validate_attachment_differences(ec2, eni, attachment_before, attachment_after, differences):
    if "instance_id" in differences or "device_index" in differences:
        verify_detachment_possible(attachment_before)
        verify_attachment_possible(ec2, eni, attachment_after)


def process_attachment_differences(ec2, eni, attachment_before, attachment_after, differences):
    # operation ordering is important here, as we may need to reattach first and just do
    # everything in one operation
    # we also reattach when we're just changing the device index
    if "instance_id" in differences or "device_index" in differences:
        verify_detachment_possible(attachment_before)
        verify_attachment_possible(ec2, eni, attachment_after)
        detach_and_wait(eni)
        do_new_attachment(ec2, eni, attachment_after)
        # we've also processed keep_on_termination here
        return

    # if we get to here, other attachment properties don't differ,
    # so we just modify the existing attachment
    if "keep_on_termination" in differences:
        existing_attachment_id = eni.attachment["AttachmentId"]
        kot = attachment_after.keep_on_termination
        if kot is None:
            kot = True
        apply_keep_on_termination_policy(eni, existing_attachment_id, kot)
        eni.load()


def validate_eni_differences(ec2, eni, entity_before, entity_after, differences):
    for difference in differences:
        if difference in ("description", "tags", "source_dest_check"):
            # no validations
            pass
        elif difference == "security_groups":
            for sg in entity_after.security_groups:
                validate_security_group(ec2, sg, eni.vpc_id)
        elif difference == "state":
            if entity_before.state == "detached":
                verify_attachment_possible(ec2, eni, entity_after.attachment)
            else:
                verify_detachment_possible(entity_before.attachment)
        elif difference == "attachment":
            if "state" not in differences:
                attachment_differences = entity_before.attachment.differing_properties_to(
                    entity_after.attachment)
                Attachment.validate_prohibited_differing_properties(attachment_differences)
                validate_attachment_differences(ec2, eni,
                                                entity_before.attachment,
                                                entity_after.attachment,
                                                attachment_differences)
        else:
            raise AssertionError("Unexpected eni difference: {0}.".format(difference))


def process_eni_differences(ec2, eni, entity_before, entity_after, differences):
    for difference in differences:
        if difference == "description":
            eni.modify_attribute(Description={"Value": entity_after.description})
        elif difference == "security_groups":
            # accepts ids, replaces existing
            eni.modify_attribute(Groups=entity_after.security_groups)
        elif difference == "tags":
            tag_diff = tag_utils.get_diff(None, entity_after.tags, entity_before.tags)
            # we always clear existing here because we've done the processing already
            tag_update, tag_remove = tag_utils.from_diff(tag_diff, clear_existing=True)
            tag_utils.update_resource(eni, tag_update, tag_remove)
        elif difference == "source_dest_check":
            eni.modify_attribute(SourceDestCheck={"Value": entity_after.source_dest_check})
        elif difference == "state":
            # assumption: attaching requires the attachment parameter
            if entity_before.state == "detached":
                # detached -> attached
                do_new_attachment(ec2, eni, entity_after.attachment)
            else:
                # attached -> detached
                detach_and_wait(eni)
        elif difference == "attachment":
            # assumption: this is when modifying the attachment attribute, could be reattachment,
            # could be a modification of the device index or the keep on termination attribute
            # pure attachment/detachment is handled with a difference in "state",
            # so this ignores that case
            if "state" not in differences:
                attachment_differences = entity_before.attachment.differing_properties_to(
                    entity_after.attachment)
                process_attachment_differences(ec2, eni,
                                               entity_before.attachment,
                                               entity_after.attachment,
                                               attachment_differences)
        else:
            raise AssertionError("Unexpected eni difference: {0}.".format(difference))


def ensure_present(ec2, entity_params, check_mode):
    """
    :return: (changed, diff, result)
    :rtype: typing.Tuple[bool, dict, dict]
    """
    changed = False
    eni = identify_existing_eni(ec2, entity_params)

    if eni is None:
        entity_initial = ModuleEntityUnit()
        subnet = ec2_subnet_utils.get_subnet_by_id(ec2, entity_params.subnet_id,
                                                   fail_nonexisting_id=True)
        changed = True
        if check_mode:
            result = entity_initial\
                .build_desired_state_with_params(entity_params)\
                .with_placeholders()
            diff = entity_initial.ansible_diff_to(result)
            return changed, diff, result.to_module_return()
        else:
            eni = create_new_eni(ec2, subnet, entity_params)
    else:
        entity_initial = NetworkInterface.from_boto_dict(eni.meta.data)

    entity_ensured_created = NetworkInterface.from_boto_dict(eni.meta.data)
    entity_desired = entity_ensured_created.build_desired_state_with_params(entity_params)

    differences = entity_ensured_created.differing_properties_to(entity_desired)
    changed |= any(differences)
    NetworkInterface.validate_prohibited_differing_properties(differences)

    validate_eni_differences(ec2, eni, entity_ensured_created, entity_desired, differences)
    if check_mode:
        return (changed,
                entity_initial.ansible_diff_to(entity_desired),
                entity_desired.to_module_return())
    process_eni_differences(ec2, eni, entity_ensured_created, entity_desired, differences)

    eni.load()
    entity_final = NetworkInterface.from_boto_dict(eni.meta.data)
    return changed, entity_initial.ansible_diff_to(entity_final), entity_final.to_module_return()


def ensure_absent(ec2, params_entity, check_mode):
    """
    :type params_entity: NetworkInterface
    :type check_mode: bool

    :return: (changed, diff)
    :rtype: typing.Tuple[bool, typing.Optional[dict]]
    """
    try:
        boto_resource = identify_existing_eni(ec2, params_entity)
    except errors.ObjectDoesNotExist:
        return False, None
    if boto_resource is None:
        return False, None

    entity_initial = NetworkInterface.from_boto_dict(boto_resource.meta.data)
    if not check_mode:
        detach_and_wait(boto_resource)
        boto_resource.delete()
    return True, entity_initial.ansible_diff_to(ModuleEntityUnit())


def do_custom_validation(module_params):
    if module_params["state"] == "detached" and module_params["attachment"]:
        raise errors.ValidationError("Specifying an attachment when state is detached "
                                     "is not allowed.")

    if module_params.get("id") is None and module_params.get("subnet") is None:
        raise errors.ValidationError("When not specifying id, subnet is required.")


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            subnet=dict(),
            ip=dict(),
            security_groups=dict(type="list"),
            clear_security_groups=dict(type="bool", default=False),
            state=dict(
                choices=("attached", "detached", "absent"),
                default="attached"
            ),
            source_dest_check=dict(type="bool"),
            type=dict(
                choices=("normal", "efa"),
                default="normal"
            ),
            attachment=dict(
                type="dict",
                options=dict(
                    instance=dict(required=True),
                    device_index=dict(type="int"),
                    keep_on_termination=dict(type="bool")
                ),
            ),
            **spec.params("auth", "id", "tags", "clear_tags", "name", "description")
        ),
        required_if=[
            ("state", "attached", ("attachment",)),
            ("clear_security_groups", True, ("security_groups",))
        ]
    )

    try:
        do_custom_validation(module.params)

        ec2 = boto.ec2_resource(module.params["auth"])
        param_entity = NetworkInterface.from_module_params(module.params)

        if module.params["state"] in ("attached", "detached"):
            changed, diff, result = ensure_present(ec2, param_entity, module.check_mode)
        else:
            changed, diff = ensure_absent(ec2, param_entity, module.check_mode)
            result = None
    except errors.AwsCollectionError as e:
        module.fail_json(msg="{0}: {1}".format(e.__class__.__name__, str(e)))
    # noinspection PyUnboundLocalVariable
    module.exit_json(changed=changed, object=result, diff=diff)


if __name__ == "__main__":
    main()
