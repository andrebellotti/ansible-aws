#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "XLAB Steampunk",
}

DOCUMENTATION = """
module: s3_bucket

author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)

short_description: Manage S3 bucket

description:
  - Creation and deletion of an AWS S3 bucket.

extends_documentation_fragment:
  - steampunk.aws.auth

options:
  state:
    description:
      - Target state of the Bucket.
      - If absent, it will delete bucket even if it is not empty.
    type: str
    choices: [ present, absent ]
    default: present
  name:
    description:
      - Name of S3 bucket. Not every string is an acceptable bucket name.
      - The name must be unique across all existing bucket names in Amazon S3.
      - See U(https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html)
    required: true
    type: str
  versioning:
    description:
      - Enables you to keep multiple versions of an object in the same bucket.
    type: str
    choices: [ enabled, suspended ]
    default: suspended
  access_logging:
    description:
      - Access logging provides records for the requests
        that are made to a bucket.
    default: false
    type: bool
  public_access:
    description:
      - Ensure that public access to your S3 buckets and objects is blocked.
    default: false
    type: bool
"""

EXAMPLES = """
- name: Create an S3 bucket
  s3_bucket:
    state: present
    name: xbucket-2020-02-11-1581427332
    public_access: true
"""

RETURN = """
object:
    description:
    - Representation of the S3 bucket in the format returned
      by the boto3 client.
    - See
      U(https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#client)
      for details.
    returned: success
    type: dict
"""

import datetime

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, errors,
)


def already_exists(bucket):
    return bucket.creation_date is not None


def grant_log_delivery_premissions(bucket):
    uri = 'http://acs.amazonaws.com/groups/s3/LogDelivery'
    acl = bucket.Acl()

    acl.put(
        AccessControlPolicy=dict(
            Grants=[
                dict(
                    Grantee=dict(Type='Group', URI=uri),
                    Permission='WRITE',
                ),
                dict(
                    Grantee=dict(Type='Group', URI=uri),
                    Permission='READ_ACP',
                ),
            ],
            Owner=acl.owner,
        ),
    )


def get_dict_of_params(bucket):
    """
    Returns dict of configured parameters from bucket object
    """
    current = dict(
        versioning=(bucket.Versioning().status or 'suspended').lower(),
        access_logging=len(bucket.Logging().logging_enabled or {}) != 0,
    )

    try:
        access = bucket.meta.client.get_public_access_block(Bucket=bucket.name)
        current["public_access"] = not(
            access["PublicAccessBlockConfiguration"]["BlockPublicAcls"]
            and access["PublicAccessBlockConfiguration"]["IgnorePublicAcls"]
            and access["PublicAccessBlockConfiguration"]["BlockPublicPolicy"]
            and access["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"]
        )
    except boto.ClientError as e:
        if e.operation_name != "GetPublicAccessBlock":
            raise
        current["public_access"] = True

    return current


def bucket_diff(current, desired):
    """
    Get diff of current and desired dict of parameters.
    (What is configured and what one wants to configure)

    returns:
        {
            'access_logging': (False, True),
            'public_access': (...),
        }
    """
    diff = dict()

    for key, value in current.items():
        if desired[key] is None:
            continue
        if value != desired[key]:
            diff[key] = (value, desired[key])

    return diff


def set_access_logging(bucket, param):
    if param is None:
        return

    elif param:
        grant_log_delivery_premissions(bucket)
        bucket.Logging().put(
            BucketLoggingStatus=dict(
                LoggingEnabled=dict(
                    TargetBucket=bucket.name,
                    TargetPrefix="",
                ),
            ),
        )

    else:
        bucket.Logging().put(BucketLoggingStatus=dict())


def set_public_access(bucket, param):
    if param is None:
        return

    elif not param:
        # Block all public access
        bucket.meta.client.put_public_access_block(
            Bucket=bucket.name,
            PublicAccessBlockConfiguration=dict(
                BlockPublicAcls=True,
                IgnorePublicAcls=True,
                BlockPublicPolicy=True,
                RestrictPublicBuckets=True,
            ),
        )

    else:
        # Allow all public access
        bucket.meta.client.put_public_access_block(
            Bucket=bucket.name,
            PublicAccessBlockConfiguration=dict(
                BlockPublicAcls=False,
                IgnorePublicAcls=False,
                BlockPublicPolicy=False,
                RestrictPublicBuckets=False,
            ),
        )


def set_versioning(bucket, param):
    if param is None:
        return

    elif param == 'enabled':
        bucket.Versioning().enable()

    else:
        bucket.Versioning().suspend()


def set_bucket_params(bucket, params):
    set_public_access(bucket, params['public_access'])
    set_versioning(bucket, params['versioning'])
    set_access_logging(bucket, params['access_logging'])


def create_bucket(bucket, params, check_mode):
    result = dict(
        creation_date=datetime.datetime.now(),
        public_access=params['public_access'],
        versioning=params['versioning'],
        access_logging=params['access_logging'],
    )

    if check_mode:
        return True, result

    location = {'LocationConstraint': bucket.meta.client.meta.region_name}
    bucket.create(CreateBucketConfiguration=location)
    result['creation_date'] = bucket.creation_date

    set_bucket_params(bucket, params)

    return True, result


def update_bucket(bucket, params, check_mode):
    buckets_diff = bucket_diff(get_dict_of_params(bucket), params)
    result = dict(
        creation_date=bucket.creation_date,
        public_access=params['public_access'],
        versioning=params['versioning'],
        access_logging=params['access_logging'],
    )

    if not buckets_diff:
        return False, result

    if check_mode:
        return True, result

    set_bucket_params(bucket, params)

    return True, result


def ensure_present(s3, params, check_mode):
    bucket = s3.Bucket(params['name'])

    if already_exists(bucket):
        return update_bucket(bucket, params, check_mode)

    return create_bucket(bucket, params, check_mode)


def ensure_absent(s3, params, check_mode):
    bucket = s3.Bucket(params['name'])

    if not already_exists(bucket):
        return False

    if not check_mode:
        bucket.objects.all().delete()
        bucket.delete()

    return True


def main():
    module_args = dict(
        spec.params('state', 'name', 'auth', service='s3'),
        versioning=dict(
            type='str',
            choices=['enabled', 'suspended'],
            default='suspended',
        ),
        access_logging=dict(
            default=False,
            type='bool',
        ),
        public_access=dict(
            default=False,
            type='bool',
        ),
    )

    module = AnsibleModule(argument_spec=module_args,
                           supports_check_mode=True)

    try:
        s3 = boto.s3_resource(module.params['auth'])
        if module.params['state'] == 'present':
            changed, bucket = ensure_present(s3, module.params, module.check_mode)
        else:
            changed = ensure_absent(s3, module.params, module.check_mode)
            bucket = None
        module.exit_json(changed=changed, object=bucket)

    except errors.AwsCollectionError as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
