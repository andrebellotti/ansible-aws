# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = """
options:
  auth:
    description:
      - Parameters for authenticating with the AWS service.
        Each of them may be defined via environment variables.
    type: dict
    suboptions:
      access_key:
        description:
          - The AWS access key.
            If not set, the value of the AWS_ACCESS_KEY environment
            variable will be checked.
        type: str
        required: true
      secret_key:
        description:
          - The AWS secret key.
            If not set, the value of the AWS_SECRET_KEY environment
            variable will be checked.
        type: str
        required: true
      region:
        description:
          - Name of the AWS region.
          - If not set, the value of the AWS_REGION environment
            variable will be checked.
        type: str
        required: true
      url:
        description:
          - URL to the AWS service related to the resource.
            By default, this is automatically determined through the region parameter.
          - If not set explicitly, the value of the AWS_<SERVICE>_URL environment variable
            will be used.
          - The services currently supported are EC2 and S3.
        type: str
        required: false
"""
