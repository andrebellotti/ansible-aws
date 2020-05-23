# -*- coding: utf-8 -*-
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GPLv3
from ansible.plugins.action import ActionBase
# GPLv3
from ansible.utils.vars import merge_hash

from ansible_collections.steampunk.aws.plugins.module_utils.ec2_key_pair_utils import \
    fingerprints_equal, local_ssh_key_to_md5_fingerprint
from ansible_collections.steampunk.aws.plugins.module_utils.errors import \
    KeyPairFingerprintError


def intercept_module_args(**kwargs):
    """
    Compute the public key fingerprints on the controller to avoid having a remote dependency on
    cryptography.

    Only relevant if a public_key is provided.

    If no fingerprints are provided, injects the MD5 fingerprint into the fingerprints parameter.
    If any fingerprints are provided, _at least one_ must match the computed MD5 fingerprint,
    lest an error is thrown.
    A missing MD5 fingerprint is injected, e.g. if no MD5 fingerprint is provided, the computed
    fingerprint is added to the fingerprint list.
    """
    result = kwargs.copy()

    if not ("public_key" in result and result["public_key"] is not None):
        return result

    fp_md5 = local_ssh_key_to_md5_fingerprint(result["public_key"])

    if "fingerprints" in result and result["fingerprints"]:
        # verify that at least one fingerprint is correct
        correct_fingerprints = [
            user_fingerprint
            for user_fingerprint in result["fingerprints"]
            if fingerprints_equal(fp_md5, user_fingerprint)
        ]

        if not any(correct_fingerprints):
            raise KeyPairFingerprintError("None of the provided fingerprints match the MD5 "
                                          "fingerprint of the public key (MD5={0})"
                                          .format(fp_md5))
    else:
        result["fingerprints"] = []

    # make sure the md5 fingerprint is always present
    if not any(fp for fp in result["fingerprints"] if fingerprints_equal(fp, fp_md5)):
        result["fingerprints"].append(fp_md5)

    return result


class ActionModule(ActionBase):
    def run(self, *args, **kwargs):
        super_result = super(ActionModule, self).run(*args, **kwargs)
        wrap_async = self._task.async_val and not self._connection.has_native_async

        task_vars = kwargs.pop("task_vars", None)
        self._task.args = intercept_module_args(**self._task.args)
        module_result = self._execute_module(
            module_name="steampunk.aws.ec2_key_pair",
            module_args=self._task.args,
            task_vars=task_vars,
            wrap_async=wrap_async
        )

        return merge_hash(super_result, module_result)
