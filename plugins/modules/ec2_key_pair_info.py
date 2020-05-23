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
module: ec2_key_pair_info
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: List EC2 key pairs.
description:
  - Retrieve information about AWS EC2 key pairs.
extends_documentation_fragment:
  - steampunk.aws.auth
options:
  names:
    description:
      - The names of the keypairs to retrieve.
    default: []
    required: false
    type: list
seealso:
  - module: ec2_key_pair
"""

# language=yaml
EXAMPLES = """
- name: List all EC2 key pairs
  ec2_key_pair_info:
  register: result

- name: List a specific EC2 key pair
  ec2_key_pair_info:
    names: my-first-keypair
  register: result

- name: List information for multiple key pairs
  ec2_key_pair_info:
    names:
      - my-first-keypair
      - world-greeter
  register: result
"""

# language=yaml
RETURN = """
objects:
  description:
    - A list of objects representing EC2 key pairs.
    - Note that the private keys are not returned, as they are not stored by AWS EC2.
  type: list
  returned: success
  contains:
    name:
      description: The name of the key pair.
      type: str
      returned: always
    fingerprint:
      description:
        - This keypair's fingerprint.
        - Note that AWS computes fingerprints in two different ways -
          for AWS-generated keys, fingerprints are computed with SHA1 on the _private_ keys,
          while for imported keys, fingerprints are computed with MD5 on the _public_ keys.
      type: str
      returned: always
  sample:
    objects:
      - name: my-first-keypair
        fingerprint: "0a:ec:24:7b:69:ce:98:63:a4:ea:3c:e6:76:bb:6c:66:90:d0:33:ae"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.steampunk.aws.plugins.module_utils import \
    spec, ec2_filters, boto, ec2_key_pair_utils


def get_keypairs(client, filter_mapping, params):
    """
    :type client: pyboto3.ec2
    :type filter_mapping: dict
    :type params: dict
    :rtype: list
    """
    filters = ec2_filters.build_from_mapping(filter_mapping, params)
    keypair_struct = client.describe_key_pairs(Filters=filters)
    keypairs = keypair_struct["KeyPairs"]
    return keypairs


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            names=dict(
                type="list",
                default=[]
            ),
            **spec.params("auth")
        )
    )

    filter_mapping = dict(
        names="key-name",
    )

    result = []
    try:
        client = boto.ec2_client(module.params["auth"])
        keypairs = get_keypairs(client, filter_mapping, module.params)
        result = [ec2_key_pair_utils.boto_dict_to_module_return(kp) for kp in keypairs]
    except Exception as e:
        module.fail_json(msg="{0}: {1}".format(type(e), str(e)))
    module.exit_json(changed=False, objects=result)


if __name__ == "__main__":
    main()
