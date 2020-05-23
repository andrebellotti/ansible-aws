# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.


from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from ansible.module_utils.basic import missing_required_lib

from ansible_collections.steampunk.aws.plugins.module_utils import boto
from ansible_collections.steampunk.aws.plugins.module_utils.errors import (
    SSHKeyError, MissingDependencyError, ObjectDoesNotExist,
)

# for locally-generated keys, MD5 on public keys is used, SHA1 on private for remotely generated
FINGERPRINT_MD5_BITS = 128


def get_key_pair_by_name(ec2, name):
    """
    Retrieves the key pair named key_pair_name.
    :raises errors.ObjectDoesNotExist: when key pair does not exist.
    """
    key_pair = ec2.KeyPair(name)
    try:
        key_pair.load()
    except boto.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
            raise ObjectDoesNotExist(
                'Key pair with name {0} does not exist'.format(name)
            )
        raise
    return key_pair


def _format_hex_fingerprint(rawhex):
    return ":".join(rawhex[a:(a + 2)] for a in range(0, len(rawhex), 2))


def local_ssh_key_to_md5_fingerprint(key):
    """
    Converts an SSH key to a fingerprint.

    This only computes the MD5 fingerprint of the public key in the OpenSSH format.

    AWS computes fingerprints for AWS-generated keys with SHA1 and of the _private_ keys,
    this is not what this function does. We don't even have access to private keys.

    :type key: str
    :return: fingerprint_md5
    :rtype: str
    """
    if not HAS_CRYPTOGRAPHY:
        # this is only accessed in the action plugin, so it is a controller dependency
        raise MissingDependencyError(missing_required_lib(
            "cryptography",
            reason="on the controller to generate key pair fingerprints"
        ))

    parts = key.split()

    if not (1 < len(parts) < 4):
        raise SSHKeyError("The SSH public key must be composed of 2 or 3 parts.")

    if parts[0].lower() != "ssh-rsa":
        raise SSHKeyError("AWS EC2 only supports RSA key pairs.")

    pubkey_pem = serialization.load_ssh_public_key(key.encode("utf-8"), default_backend())
    pubkey_bytes_der = pubkey_pem.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fingerprint_md5_hex = hashlib.md5(pubkey_bytes_der).hexdigest()
    fingerprint_md5_formatted = _format_hex_fingerprint(fingerprint_md5_hex)

    return fingerprint_md5_formatted


def fingerprints_equal(fp1, fp2):
    """
    :type fp1: str
    :type fp2: str
    :rtype: bool
    """
    return fp1.lower() == fp2.lower()


def _fingerprint_check(fp, fp_bits):
    """
    :type fp: str
    :type fp_bits: int
    :rtype: bool
    """
    # fingerprint to hex (2^4 = 16 bits per char)
    # + colons every two characters (without the final one)
    fp_length_full = int(fp_bits / 4 + (fp_bits / (4 * 2) - 1))
    # 16 bits per char, two chars per part
    fp_part_count = int(fp_bits / (4 * 2))

    split = fp.split(":")
    length_check = len(fp) == fp_length_full
    split_length_check = len(split) == fp_part_count
    split_parts_check = all(len(s) == 2 for s in split)
    split_contents_check = all(all(c.isalnum() for c in part) for part in split)
    return length_check and split_length_check and split_parts_check and split_contents_check


def fingerprint_is_md5(fp):
    """
    :type fp: str
    :rtype: bool
    """
    return _fingerprint_check(fp, FINGERPRINT_MD5_BITS)


def boto_dict_to_module_return(boto_dict):
    """
    :type boto_dict: dict
    :rtype: dict
    """
    optional_return = {}
    if "KeyMaterial" in boto_dict:
        optional_return["key_material"] = boto_dict["KeyMaterial"]
    return dict(
        name=boto_dict["KeyName"],
        fingerprint=boto_dict["KeyFingerprint"],
        **optional_return
    )
