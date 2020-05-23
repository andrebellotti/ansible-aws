# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import missing_required_lib

from ansible_collections.steampunk.aws.plugins.module_utils import (
    errors
)

HAS_BOTO3 = True

try:
    import boto3
    from botocore.exceptions import \
        ClientError, EndpointConnectionError, HTTPClientError  # noqa: F401
except ImportError:
    HAS_BOTO3 = False


def ec2_resource(auth):
    return _service_resource(auth, 'ec2')


def s3_resource(auth):
    return _service_resource(auth, 's3')


def _call_service_check_endpoint(service_name, resource):
    if service_name == "ec2":
        resource.meta.client.describe_regions()
    elif service_name == "s3":
        resource.meta.client.list_buckets()
    else:
        raise AssertionError("Unknown service for auth validation: {0}.".format(service_name))


def verify_auth_success(service_name, resource):
    try:
        _call_service_check_endpoint(service_name, resource)
    except ClientError as e:
        code = e.response['Error']['Code']
        if code in ('AuthFailure', 'Blocked', 'InvalidClientTokenId',
                    'MissingAuthenticationToken', 'PendingVerification'):
            raise errors.AuthenticationError(
                "Unable to authenticate with AWS with the provided credentials: {0}. "
                "Check your 'auth.access_key', 'auth.secret_key' and 'auth.region' parameters"
                .format(code)
            )
        raise
    except EndpointConnectionError as e:
        raise errors.AuthenticationError("Unable to authenticate with AWS on endpoint {0}"
                                         .format(e.kwargs['endpoint_url']))
    except HTTPClientError as e:
        raise errors.AuthenticationError("Unable to perform an HTTP connection: {0}".format(str(e)))


def _url_or_region_default(url, service, region):
    if url:
        return url
    return "https://{0}.{1}.amazonaws.com/".format(service, region)


def _service_resource(auth, service_name):
    try:
        resource = _session(auth).resource(
            service_name,
            endpoint_url=_url_or_region_default(auth.get('url'), service_name, auth['region'])
        )
    except ValueError as e:
        raise errors.ValidationError("Unable to connect to AWS: {0}".format(str(e)))

    verify_auth_success(service_name, resource)
    return resource


def ec2_client(auth):
    """
    :rtype: pyboto3.ec2
    """
    return _client(auth, 'ec2')


def s3_client(auth):
    return _client(auth, 's3')


# TODO(@mancabizjak): retire when all modules use resources
def _client(auth, service):
    return _session(auth).client(
        service,
        endpoint_url=_url_or_region_default(auth.get('url'), service, auth['region']),
    )


def _session(auth):
    if not HAS_BOTO3:
        raise Exception(missing_required_lib('boto3'))

    return boto3.Session(
        aws_access_key_id=auth['access_key'],
        aws_secret_access_key=auth['secret_key'],
        region_name=auth['region'],
    )
