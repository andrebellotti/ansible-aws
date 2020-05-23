# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.


from __future__ import absolute_import, division, print_function
__metaclass__ = type


class AwsCollectionError(Exception):
    def __init__(self, message):
        """
        :type message: str
        """
        super(AwsCollectionError, self).__init__(message)


class AuthenticationError(AwsCollectionError):
    pass


class SSHKeyError(AwsCollectionError):
    pass


class KeyPairFingerprintError(AwsCollectionError):
    pass


class DisallowedOperationError(AwsCollectionError):
    pass


class MissingDependencyError(AwsCollectionError):
    pass


class ObjectDoesNotExist(AwsCollectionError):
    pass


class ValidationError(AwsCollectionError):
    pass


class AmbiguousObjectError(AwsCollectionError):
    pass


class UnexpectedStateError(AwsCollectionError):
    pass
