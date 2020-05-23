# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import env_fallback


def params(*param_names, **kwargs):
    """ Returns argument specification for the arguments common
        to several modules in the collection.
    """
    # python2 compatibility, can't have default values after variadic
    # https://www.python.org/dev/peps/pep-3102/
    service = kwargs.pop('service', 'ec2')
    if kwargs:
        raise AssertionError("'service' is the only supported keyword argument to params(...)")

    spec = {}
    for p in param_names:
        if p == 'auth':
            spec[p] = _auth_for(service)
        else:
            spec[p] = _COMMON[p]
    return spec


_COMMON = dict(
    state=dict(
        default="present",
        choices=["present", "absent"],
    ),
    name=dict(),
    names=dict(
        type='list',
        default=[],
    ),
    description=dict(),
    id=dict(),
    ids=dict(
        type='list',
        default=[],
    ),
    tags=dict(
        type="dict",
        default={},
    ),
    clear_tags=dict(
        type="bool",
        default=False,
    ),
    filters=dict(
        type="dict",
        default={},
    ),
    availability_zone=dict()
)


def _auth_for(service):
    return dict(
        type="dict",
        apply_defaults=True,
        options=dict(
            access_key=dict(
                fallback=(env_fallback, ['AWS_ACCESS_KEY']),
                required=True
            ),
            secret_key=dict(
                no_log=True,
                fallback=(env_fallback, ['AWS_SECRET_KEY']),
                required=True
            ),
            region=dict(
                fallback=(env_fallback, ['AWS_REGION']),
                required=True
            ),
            url=dict(
                fallback=(env_fallback, [_service_var(service)]),
            ),
        ),
    )


def _service_var(service):
    if service.lower() not in ['ec2', 's3']:
        raise AssertionError('unsupported service: {0}'.format(service))
    return 'AWS_{0}_URL'.format(service.upper())
