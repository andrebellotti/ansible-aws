# -*- coding: utf-8 -*-
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from datetime import datetime
try:
    from datetime import timezone
    utc = timezone.utc
except ImportError:  # Work-around for python 2.7
    from datetime import tzinfo, timedelta

    class UTC(tzinfo):
        def utcoffset(self, dt):
            return timedelta(0)

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return timedelta(0)
    utc = UTC()

from ansible_collections.steampunk.aws.plugins.module_utils import (
    boto, errors, tag_utils, ec2_security_group_utils
)


"""
States that describe an instance that exists on EC2.
Terminated state is excluded, we treat it as "no longer present",
despite the fact that the records about terminated instances
remain visible for a short period after their termination.
"""
PRESENT_STATES = frozenset([
    'pending',
    'running',
    'stopping',
    'stopped',
    'shutting-down',
])


def get_instance_by_id(ec2, instance_id,
                       fail_nonexisting_id=False,
                       fail_terminated=False):
    instance = ec2.Instance(instance_id)
    try:
        instance.load()
    except boto.ClientError as e:
        if (fail_nonexisting_id and
                'InvalidInstanceID' in e.response['Error']['Code']):
            # InvalidInstanceID.Malformed
            # InvalidInstanceID.NotFound
            raise errors.ObjectDoesNotExist(
                'Instance with id {0} does not exist'.format(instance_id)
            )
        return None
    # We may have successfully retrieved a terminated instance.
    # We treat terminated instances as not present anymore, but again give
    # the caller a choice on how to proceed.
    if instance.state['Name'] == 'terminated':
        # Optionally fail for callers that need non-terminated instances
        if fail_terminated:
            raise errors.UnexpectedStateError(
                "Instance with id {0} is terminated".format(instance_id)
            )
        return None

    return instance


def security_groups_from_boto(security_groups):
    return sorted([sg['GroupId'] for sg in security_groups])


def primary_network_interface_from_boto(network_interfaces_attr):
    for i in network_interfaces_attr:
        if i['Attachment']['DeviceIndex'] == 0:
            return i['NetworkInterfaceId']


def secondary_network_interfaces_from_boto(network_interfaces_attr):
    interfaces = [
        i['NetworkInterfaceId']
        for i in sorted(
            network_interfaces_attr,
            key=lambda x: x['Attachment']['DeviceIndex']
        )
    ]
    return interfaces[1:]  # report all except the primary one


def monitoring_from_boto(monitoring):
    if monitoring['State'] == 'disabled':
        return 'basic'
    return 'detailed'


def shutdown_behavior_from_boto(instance):
    resp = instance.describe_attribute(
        Attribute='instanceInitiatedShutdownBehavior',
    )
    return resp['InstanceInitiatedShutdownBehavior']['Value']


def result_from_params(ec2, params, subnet):
    result = dict(
        id='generated-by-aws',
        launched_at=datetime.now(tz=utc).isoformat(),
        type=params['type'],
        ami=params['ami'],
        vpc=subnet.vpc.id,
        subnet=subnet.id,
        availability_zone=subnet.availability_zone_id,
        security_groups=params['security_groups'] or [
            ec2_security_group_utils.get_default_security_group_for_vpc(ec2, subnet.vpc.id).id
        ],
        network_interface=params['network_interface'] or 'generated-by-aws',
        secondary_network_interfaces=[],
        key_pair=params['key_pair'],
        tenancy=params['tenancy'],
        monitoring=params['monitoring'],
        on_instance_initiated_shutdown=params['on_instance_initiated_shutdown'],
        tags=tag_utils.merge_with_name_param(params['name'], params['tags']),
    )

    return result


def result_from_remote(instance):
    result = dict(
        id=instance.id,
        launched_at=instance.launch_time.isoformat(),
        state=instance.state["Name"],
        type=instance.instance_type,
        ami=instance.image_id,
        vpc=instance.vpc_id,
        subnet=instance.subnet_id,
        availability_zone=instance.subnet.availability_zone_id,
        security_groups=security_groups_from_boto(
            instance.security_groups
        ),
        network_interface=primary_network_interface_from_boto(
            instance.network_interfaces_attribute
        ),
        secondary_network_interfaces=secondary_network_interfaces_from_boto(
            instance.network_interfaces_attribute
        ),
        key_pair=instance.key_name,
        tenancy=instance.placement['Tenancy'],
        monitoring=monitoring_from_boto(instance.monitoring),
        on_instance_initiated_shutdown=shutdown_behavior_from_boto(instance),
        tags=tag_utils.from_boto3(instance.tags or []),
    )

    return result
