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
module: ec2_instance
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: Manage EC2 instances
description:
  - Create, update or delete an AWS EC2 instance.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.id
  - steampunk.aws.tags
  - steampunk.aws.clear_tags
options:
  state:
    description:
      - The desired state of the EC2 instance.
      - When creating a new instance, the default behavior of the module
        is to wait until the instance is in running state on AWS.
        Set I(wait_state) to C(false) to modify this behavior.
      - Note that terminated instances are treated as absent.
    choices: [ present, absent ]
    default: present
    type: str
  wait_state:
    description:
      - Whether the module should wait (block) until I(state) is reached.
      - For newly created instances - if I(state) is C(present) and this
        parameter is set, the module ensures a running instance. Otherwise
        it ensures an instance that exists on AWS, but is not necessarily in
        running state.
      - Note that this parameter has no effect when you're updating an existing
        instance.
      - If I(state) is C(absent) and this parameter is set, the module initiates
        instance termination and continues.
        Otherwise it waits until the instance is terminated.
    type: bool
    default: true
  name:
    description:
      - Name tag for the EC2 instance.
      - This parameter is required when creating a new instance.
      - In the absence of I(id) and I(network_interface), the value of this
        parameter will be used in conjunction with I(ami) and I(subnet) to
        identify the instance.
    type: str
  ami:
    description:
      - ID of the Amazon Machine Image used to launch the instance.
      - This parameter is required when creating a new instance.
      - In the absence of I(id) and I(network_interface), the value of this
        parameter will be used in conjunction with I(name) and I(subnet) to
        identify the instance.
    type: str
  type:
    description:
      - Type of the EC2 instance.
      - This parameter is required when creating a new instance.
      - Currently it is not possible to modify the instance type after
        an instance is launched.
    type: str
  key_pair:
    description:
      - Name of the key pair to be used when connecting to the instance.
      - This parameter is required when creating an instance.
    type: str
  availability_zone:
    description:
      - ID of the availability zone in which to create the instance.
      - This parameter is required when creating an instance if neither
        I(subnet) nor I(network_interface) are specified.
      - If C(subnet) is provided, this parameter is ignored.
      - If C(id) is not provided, at least one of I(subnet),
        I(availability_zone) is required.
    type: str
  subnet:
    description:
      - ID of the subnet where the instance will be launched from.
      - This parameter is required when creating an instance if neither
        I(availability_zone) nor I(network_interface) are specified.
      - If omitted, the instance will be created in the default subnet for
        the availability zone specified in C(availability_zone) of
        the default VPC for I(auth.region).
    type: str
  network_interface:
    description:
      - ID of an existing ENI to attach to the instance as the primary
        network interface (at device index 0).
      - This parameter is required when creating an instance if you don't
        provide I(subnet) or I(availability_zone). If I(network_interface)
        points to an ENI that is already attached as a primary network
        interface for an instance, the module uses it to uniquely identify
        the instance.
      - If this parameter is provided, the instance will be created in the
        subnet of the network interface.
      - If this parameter is omitted when creating an instance, a default
        primary network interface will be automatically created and attached,
        and you can optionally set I(security_groups) to configure it.
      - Note that the I(network_interface) cannot be modified after instance
        is launched. Use M(ec2_network_interface) to attach
        any additional ENIs to the instance.
      - This parameter is mutually exclusive with I(security_groups), I(subnet)
        and I(availability_zone).
    type: str
  security_groups:
    description:
      - IDs of security groups that will be associated with the default
        primary network interface.
      - If omitted, the VPC's default security group will be used.
      - Use this parameter if you wish to configure the default primary
        network interface that will be created automatically when a new
        instance is launched.
      - To modify security groups of the default network interface created
        for you on instance launch, use M(ec2_network_interface).
      - This parameter is mutually exclusive with I(network_interface).
    type: list
  tenancy:
    description:
      - The instance tenancy setting.
      - If omitted, the VPC's default instance tenancy setting will be used.
      - You cannot modify this setting after an instance is launched.
    type: str
    choices: [ default, dedicated ]
  monitoring:
    description:
      - Monitoring mode for the instance.
    type: str
    choices: [ basic, detailed ]
    default: basic
  on_instance_initiated_shutdown:
    description: Default behavior for instance-initiated shutdown.
    type: str
    choices: [ stop, terminate ]
    default: stop
seealso:
  - module: ec2_instance_info
  - module: ec2_network_interface
"""

EXAMPLES = """
- name: Launch an EC2 instance in a specific subnet
  ec2_instance:
    name: first-instance
    type: a1.medium
    ami: ami-0343ab73df9eb1496
    key_pair: my-keypair
    subnet: subnet-870717cd
  register: my_instance

- name: Update EC2 instance configuration
  ec2_instance:
    id: "{{ my_instance.object.id }}"
    on_instance_initiated_shutdown: terminate
    monitoring: detailed

- name: Launch another EC2 instance
  ec2_instance:
    name: second-instance
    type: t2.micro
    ami: ami-0343ab73df9eb1496
    key_pair: my-keypair
    network_interface: eni-2j66sa32jfs2f2d
    tags:
      env: staging

- name: Terminate an EC2 instance
  ec2_instance:
    id: "{{ my_instance.object.id }}"
    state: absent
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
    returned: success and I(state)=C(present)
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, ec2_instance_utils, ec2_filters, validation, errors,
    tag_utils, ec2_subnet_utils, ec2_key_pair_utils, ec2_network_interface_utils,
    diff_utils, ec2_availability_zone_utils
)


def get_instance_by_alternative_params(ec2, name, ami, subnet_id):
    instance_collection = ec2.instances.filter(
        Filters=ec2_filters.from_dict({
            'tag:Name': name,
            'image-id': ami,
            'subnet-id': subnet_id,
            'instance-state-name': list(ec2_instance_utils.PRESENT_STATES),
        })
    )
    instances = list(instance_collection)

    if not instances:
        return None

    if len(instances) > 1:
        raise errors.AmbiguousObjectError(
            "Unable to identify the instance based on name ({0}),"
            "ami ({1}) and subnet ({2})".format(name, ami, subnet_id)
        )
    instance = instances[0]
    instance.load()

    return instance


def get_instance_by_primary_network_interface(ec2, eni_id):
    eni = ec2_network_interface_utils.get_network_interface_by_id(
        ec2, eni_id, fail_nonexisting_id=True
    )
    # Eni exists - if not, error is raised above
    validate_eni_detached_or_primary(eni)

    # ENI is attached as a primary interface.
    # Use it to identify the instance
    if eni.attachment:
        return ec2_instance_utils.get_instance_by_id(
            ec2, eni.attachment['InstanceId']
        )
    # ENI exists, but is detached
    return None


def identify_instance(ec2, params, fail_nonexisting_id=False):
    validate_identification_params_presence(params)

    # If id is provided but doesn't exist, fail
    instance_id = params["id"]
    if instance_id:
        return ec2_instance_utils.get_instance_by_id(
            ec2, instance_id, fail_nonexisting_id=fail_nonexisting_id
        )

    primary_eni_id = params["network_interface"]
    if primary_eni_id:
        instance = get_instance_by_primary_network_interface(ec2, primary_eni_id)
        if instance:
            return instance

    subnet = get_subnet(ec2, params["subnet"], params["availability_zone"])
    return get_instance_by_alternative_params(
        ec2, params["name"], params["ami"], subnet.id
    )


def validate_identification_params_presence(params):
    # Either one of these suffices for uniquely identifying the instance
    if params['id'] or params['network_interface']:
        return
    # Alternatively, we need any of:
    # a) name, ami, availability_zone
    # b) name, ami, subnet
    required = ['name', 'ami']
    try:
        if not params['subnet']:
            required.append('availability_zone')
        validation.validate_presence(required, params)
    except errors.ValidationError:
        raise errors.ValidationError(
            "You must provide either id or network_interface, "
            "or all of name, ami and [subnet|availability_zone] "
            "to identify the instance"
        )


def validate_ami_reference(ec2, ami_id):
    ami = ec2.Image(ami_id)
    try:
        ami.load()
    except boto.ClientError as e:
        if 'InvalidAMIID' in e.response['Error']['Code']:
            # InvalidAMIID.Malformed
            # InvalidAMIID.NotFound
            # InvalidAMIID.Unavailable
            raise errors.ObjectDoesNotExist(
                'AMI with id {0} does not exist in your region'.format(ami_id)
            )
        raise


def validate_instance_type_reference(ec2, instance_type):
    try:
        ec2.meta.client.describe_instance_types(
            InstanceTypes=[instance_type],
        )
    except boto.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidInstanceType':
            raise errors.ObjectDoesNotExist(
                'Instance type {0} does not exist in your region'.format(instance_type)
            )
        raise


# TODO: migrate to using functionality in ec2_security_utils
def validate_security_group_references(ec2, security_groups, vpc_id):
    groups = ec2.security_groups.filter(
        Filters=ec2_filters.from_dict({
            'group-id': security_groups,
            'vpc-id': vpc_id,
        })
    )
    present_groups = {group.id for group in groups}
    invalid_refs = set(security_groups) - present_groups
    if invalid_refs:
        raise errors.ObjectDoesNotExist(
            "Security groups ({0}) do not exist in {1}".format(
                ", ".join(sorted(invalid_refs)), vpc_id
            )
        )


def validate_tenancy(tenancy, vpc):
    if vpc.instance_tenancy == 'dedicated' and tenancy == 'default':
        raise errors.ValidationError(
            "You cannot launch an instance with default tenancy in "
            "a VPC with dedicated instance tenancy"
        )


def validate_eni_detached_or_primary(eni):
    if not eni.attachment:
        return
    if eni.attachment['DeviceIndex'] != 0:
        # we're dealing with a secondary network interface, but
        # we only care for the primary one
        raise errors.ValidationError(
            "Network interface {0} is attached as a secondary "
            "network interface of an existing instance. Provide "
            "a detached network interface when creating an instance, or "
            "a primary network interface to identify an existing instance"
            .format(eni.id)
        )


def validate_params(ec2, params):
    vpc = None

    if params['subnet']:
        subnet = ec2_subnet_utils.get_subnet_by_id(ec2, params['subnet'])
        vpc = subnet.vpc
    if params['availability_zone']:
        ec2_availability_zone_utils.validate_az_id(ec2, params['availability_zone'])
        subnet = ec2_subnet_utils.get_default_subnet_for_az(
            ec2, params['availability_zone']
        )
        vpc = subnet.vpc
    if params['network_interface']:
        eni = ec2_network_interface_utils.get_network_interface_by_id(
            ec2, params['network_interface'], fail_nonexisting=True
        )
        vpc = eni.vpc
        validate_eni_detached_or_primary(eni)

    if params['security_groups']:
        validate_security_group_references(
            ec2, params['security_groups'], vpc.id
        )
    if params['tenancy']:
        validate_tenancy(params['tenancy'], vpc)
        # TODO for later: add a check to ensure instance type supports dedicated hosts

    params['type'] and validate_instance_type_reference(ec2, params['type'])
    params['ami'] and validate_ami_reference(ec2, params['ami'])
    params['key_pair'] and ec2_key_pair_utils.get_key_pair_by_name(ec2, params['key_pair'])


def validate_state_dependent_operation(instance, ok_states, operation_name):
    current_instance_state = instance.state['Name']
    if current_instance_state not in ok_states:
        raise errors.DisallowedOperationError(
            '{0} can only be modified for instances in {1} '
            '{2} ({3} is {4})'.format(
                operation_name, ", ".join(ok_states),
                "state" if len(ok_states) == 1 else "states",
                instance.id, instance.state['Name']
            )
        )


def get_subnet(ec2, subnet_id, az_id):
    if not subnet_id:  # availability_zone param is provided
        ec2_availability_zone_utils.validate_az_id(ec2, az_id)
        return ec2_subnet_utils.get_default_subnet_for_az(ec2, az_id)
    return ec2_subnet_utils.get_subnet_by_id(  # subnet param is provided
        ec2, subnet_id, fail_nonexisting_id=True
    )


def _create_payload(params, subnet):
    """
    Takes module params and constructs payload for create_instances.
    Assumes all references were validated beforehand.
    """
    payload = dict(
        MinCount=1,
        MaxCount=1,
        ImageId=params['ami'],
        InstanceType=params['type'],
        KeyName=params['key_pair'],
        TagSpecifications=[
            dict(
                ResourceType='instance',
                Tags=tag_utils.to_boto3(params['tags'], name=params['name']),
            )
        ],
        InstanceInitiatedShutdownBehavior=params['on_instance_initiated_shutdown'],
        Monitoring=dict(
            Enabled=params['monitoring'] == 'detailed'
        ),
    )
    if params['tenancy']:
        payload['Placement'] = dict(
            Tenancy=params['tenancy']
        )
    else:
        payload['Placement'] = dict(
            Tenancy=subnet.vpc.instance_tenancy
        )

    if params['security_groups']:
        payload['SecurityGroupIds'] = params['security_groups']

    if params['network_interface']:
        payload['NetworkInterfaces'] = [dict(
            NetworkInterfaceId=params['network_interface'],
            DeviceIndex=0,
        )]
    else:
        payload['SubnetId'] = subnet.id

    return payload


def create(ec2, subnet, params):
    payload = _create_payload(params, subnet)
    try:
        instances = ec2.create_instances(**payload)
    # Many things can go wrong and we cannot extend our validation
    # checks to everything. But we may catch unexpected errors where
    # they are most likely, and report them in a more user-friendly format
    except boto.ClientError as e:
        raise errors.AwsCollectionError(
            "Unable to create instance: {0}".format(
                e.response['Error']['Message']
            )
        )
    instance = instances[0]

    instance.wait_until_exists()
    if params['wait_state']:
        instance.wait_until_running()

    instance.load()
    return instance


def handle_create(ec2, params, check_mode):
    if not params['key_pair']:
        raise errors.ValidationError("key_pair must be set "
                                     "when creating an instance")
    validate_params(ec2, params)

    diff = dict(
        before={},
    )

    subnet = get_subnet(ec2, params["subnet"], params["availability_zone"])

    if check_mode:
        result = ec2_instance_utils.result_from_params(ec2, params, subnet)
        diff['after'] = result
        return True, result, diff

    instance = create(ec2, subnet, params)
    result = ec2_instance_utils.result_from_remote(instance)
    diff['after'] = result

    return True, result, diff


def instances_diff(current, params):
    diff = {}
    for (param_name, remote_val) in [
        ('type', current.instance_type),
        ('ami', current.image_id),
        ('subnet', current.subnet.id),
        ('key_pair', current.key_name),
        ('tenancy', current.placement['Tenancy']),
        ('monitoring',
         ec2_instance_utils.monitoring_from_boto(current.monitoring)),
        ('on_instance_initiated_shutdown',
         ec2_instance_utils.shutdown_behavior_from_boto(current)),
        ('security_groups',
         ec2_instance_utils.security_groups_from_boto(current.security_groups)),
        ('network_interface',
         ec2_instance_utils.primary_network_interface_from_boto(
            current.network_interfaces_attribute
         )),
    ]:
        if param_name in params and params[param_name] is not None:
            optional_args = {}
            if param_name == 'security_groups':
                optional_args['equal'] = lambda x, y: set(x) == set(y)

            attribute_diff = diff_utils.attr_diff(params, param_name, remote_val, **optional_args)
            if attribute_diff:
                diff[param_name] = attribute_diff

    return diff


def update_monitoring(instance, monitoring_type, check_mode):
    # Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html  # noqa: 501
    validate_state_dependent_operation(
        instance, ['running', 'stopped'], 'CloudWatch monitoring')

    if check_mode:
        return

    if monitoring_type == 'detailed':
        instance.monitor()
        wait_state = 'enabled'
    else:
        instance.unmonitor()
        wait_state = 'disabled'

    # modifying monitoring state is an async operation,
    # so we need to wait to ensure the desired state
    instance.wait_until_exists(
        Filters=ec2_filters.from_dict({
            'monitoring-state': wait_state,
        })
    )


def update_shutdown_behavior(instance, val, check_mode):
    # Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#Using_ChangingInstanceInitiatedShutdownBehavior  # noqa: 501
    validate_state_dependent_operation(
        instance, ['running', 'pending', 'stopping', 'stopped'],
        'Instance-initiated shutdown behavior'
    )
    if check_mode:
        return

    instance.modify_attribute(
        InstanceInitiatedShutdownBehavior=dict(
            Value=val,
        )
    )


def check_update(instance, params):
    """ Checks if update is necessary, and if it is,
        reports what needs to be updated.
    """
    diff = instances_diff(instance, params)

    current_tags = tag_utils.from_boto3(instance.tags)
    tag_diff = tag_utils.get_diff(params['name'], params['tags'], current_tags)
    tags_to_update, tags_to_remove = tag_utils.from_diff(
        tag_diff, clear_existing=params['clear_tags']
    )
    # they don't differ, do nothing
    to_update = diff or tags_to_update or tags_to_remove

    return to_update, diff, tag_diff


def update(instance, instance_diff, tag_diff, params, check_mode):
    instance_before = ec2_instance_utils.result_from_remote(instance)
    diff = dict(
        before=instance_before
    )

    update_info = copy.deepcopy(diff['before'])

    for (attr, update_attr_func) in [
        ('monitoring', update_monitoring),
        ('on_instance_initiated_shutdown', update_shutdown_behavior),
    ]:
        if attr in instance_diff:
            update_info[attr] = params[attr]
            update_attr_func(instance, params[attr], check_mode)

    if check_mode:
        updated_tags_preview = tag_utils.preview_updated_tags(
            instance_before['tags'], tag_diff, params['clear_tags']
        )
        update_info['tags'] = updated_tags_preview
        diff['after'] = update_info
        return True, update_info, diff

    if tag_diff:
        tags_to_update, tags_to_remove = tag_utils.from_diff(
            tag_diff, clear_existing=params['clear_tags']
        )
        if tags_to_update or tags_to_remove:
            tag_utils.update_resource(instance, tags_to_update, tags_to_remove)

    instance.reload()

    result = ec2_instance_utils.result_from_remote(instance)
    diff['after'] = result
    return True, result, diff


def handle_update(instance, diff, tag_diff, params, check_mode):
    immutable = [
        'ami',
        'type',
        'subnet',
        'availability_zone',
        'key_pair',
        'security_groups',
        'network_interface',
        'tenancy',
    ]
    validation.validate_update(immutable, diff)

    return update(instance, diff, tag_diff, params, check_mode)


def ensure_present(ec2, params, check_mode):
    instance = identify_instance(ec2, params, fail_nonexisting_id=True)
    if not instance:
        return handle_create(ec2, params, check_mode)

    to_update, diff, tag_diff = check_update(instance, params)
    if not to_update:
        return False, ec2_instance_utils.result_from_remote(instance), {}

    return handle_update(instance, diff, tag_diff, params, check_mode)


def ensure_absent(ec2, params, check_mode):
    instance = identify_instance(ec2, params)
    if not instance:  # already absent
        return False, {}

    # if instance is in 'shutting-down' state, termination
    # request was already sent, so we didn't change anything
    if instance.state['Name'] == 'shutting-down':
        changed = False
        diff = {}
    else:
        if not check_mode:
            instance.terminate()
        changed = True
        diff = dict(
            before=ec2_instance_utils.result_from_remote(instance),
            after={},
        )

    # Regardless of whether we initiated termination or not, we wait for
    # instance to terminate if wait_state is set
    if params['wait_state'] and not check_mode:
        instance.wait_until_terminated()

    return changed, diff


def main():
    mutually_exclusive = [
        # Making network_interface, subnet and availability_zone mutually exclusive
        # prevents user errors due to resource placement (for instance ENI not being
        # in the same AZ/subnet as pointed to by the values of these parameters).
        # This is because:
        #  if network_interface is:
        #    a) provided, the network_interface (implies) -> subnet (implies) -> availability_zone
        #    b) omitted, the primary ENI will be autogenerated in the subnet as follows:
        #       if subnet is:
        #         b1) provided, subnet (implies) -> availability_zone
        #         b2) omitted, we require availability_zone, and retrieve the default
        #             subnet for that availability zone.
        ['network_interface', 'subnet', 'availability_zone'],
        # We have two options:
        #  a) set network_interface and point it to an existing ENI. In this case,
        #     the referenced ENI already has its own security groups configured
        #     and we don't permit manipulating them here (ec2_network_interface should be used).
        #  b) if we omit network_interface we may optionally set security_groups, to
        #     configure the new ENI.
        ['network_interface', 'security_groups'],
    ]

    module = AnsibleModule(
        supports_check_mode=True,
        mutually_exclusive=mutually_exclusive,
        argument_spec=dict(
            spec.params('state', 'availability_zone', 'auth', 'name', 'tags',
                        'clear_tags', 'id'),
            wait_state=dict(
                type='bool',
                default=True,
            ),
            type=dict(),
            ami=dict(),
            key_pair=dict(),
            subnet=dict(),
            network_interface=dict(),
            security_groups=dict(
                type='list',
            ),
            monitoring=dict(
                choices=['basic', 'detailed'],
                default='basic',
            ),
            on_instance_initiated_shutdown=dict(
                choices=['stop', 'terminate'],
                default='stop',
            ),
            tenancy=dict(
                choices=['default', 'dedicated'],
            ),
        ),
    )

    try:
        ec2 = boto.ec2_resource(module.params['auth'])
        if module.params["state"] == "absent":
            result = None
            changed, diff = ensure_absent(ec2, module.params, module.check_mode)
        else:
            changed, result, diff = ensure_present(ec2, module.params, module.check_mode)

        module.exit_json(changed=changed, object=result, diff=diff)
    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
