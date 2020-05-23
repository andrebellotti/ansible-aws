# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import copy

from ansible_collections.steampunk.aws.plugins.module_utils import (
    transform
)


def to_boto3(data, name=None):
    """
    Transforms tags dictionary to the form used by boto3.
    Optionally appends the name tag, but doesn't override it.

    :type data: dict
    :type name: typing.Optional[str]
    :rtype: typing.List[dict]
    """
    # Append the name tag if it is specified, but
    # don't override it if it already exists (supports renamings)
    if name and 'Name' not in data:
        data['Name'] = name
    return transform.dict_to_list_of_structured_dicts(data, 'Key', 'Value')


def from_boto3(tag_list):
    """
    Transforms a list of tags in the format used by boto3 to a dict.

    :type tag_list: typing.List[dict]
    :rtype: dict
    """
    return transform.list_of_structured_dicts_to_dict(tag_list, 'Key', 'Value')


def merge_with_name_param(name, tags):
    """
    If name is specified, returns a new dictionary containing specified
    tags and the name tag. If tags already contains 'Name' tag and name
    parameter is set, the former takes precedence.

    :type name: typing.Optional[str]
    :type tags: dict
    :rtype: dict
    """
    # do noting, because either name param is omitted
    # or given but the explicit 'Name' from tags should take precedence
    if not name or 'Name' in tags:
        return tags

    # We have name param and no explicit 'Name' tag. Merge.
    merged_tags = copy.deepcopy(tags)
    merged_tags['Name'] = name

    return merged_tags


def _diff(desired, current):
    """
    Calculates diff between the tags of desired and current resource.
    Tags must be provided as dicts (not in boto3 format).

    :type desired: dict
    :type desired: current
    :rtype: dict
    """
    res = dict()

    desired_set, current_set = set(desired), set(current)
    tags_to_create = desired_set - current_set
    tags_to_check_for_update = desired_set & current_set
    tags_to_remove = current_set - desired_set

    for tag in tags_to_create:
        res[tag] = dict(
            before=None,
            after=desired[tag],
        )
    for tag in tags_to_remove:
        res[tag] = dict(
            before=current[tag],
            after=None
        )
    for tag in tags_to_check_for_update:
        if current[tag] != desired[tag]:
            res[tag] = dict(
                before=current[tag],
                after=desired[tag]
            )
    return res


def get_diff(name, desired_tags, remote_tags):
    """
    Calculates the tags diff.
    If the name parameter was set, it's added to the tags list, unless
    an override was specified with tags parameter or tags should be cleared.

    :type name: str
    :type desired_tags: dict
    :type remote_tags: dict
    """
    tags_to_check = desired_tags
    if name and 'Name' not in desired_tags:
        tags_to_check['Name'] = name
    return _diff(tags_to_check, remote_tags)


# TODO: refactor so that it returns tags to update as a simple
# dictionary instead of in the boto3 notation.
def from_diff(tag_diff, clear_existing=False):
    """
    Generates two sets of tags based on the previously calculated
    tag diff: tags to create or update, and tags to remove.
    The value of clear_existing is consulted to determine whether
    the tags that are present will be removed or ignored.

    Returns the tags as a list in the format used by boto3, so that it
    can be used directly as a value for Tags keyword argument.

    :type tag_diff: dict
    :type clear_existing: bool
    :rtype: (typing.List[dict], typing.List[dict])
    """
    to_update, to_remove = [], []
    for tag in tag_diff:
        new_tag_value = tag_diff[tag]['after']
        new_tag = dict(Key=tag, Value=new_tag_value)
        if new_tag_value is None:
            if clear_existing:  # we want to discard the tag
                to_remove.append(dict(Key=tag))
        else:  # we must update the tag's value
            to_update.append(new_tag)
    return to_update, to_remove


def preview_updated_tags(current_tags, tag_diff, clear_existing):
    """
    Based on the resource's current tags, previously calculated tag_diff,
    and clear_existing flag, returns the tags as they would look like after
    performing an update.
    Useful for reporting updated tags from modules running in check_mode.

    :param current_tags: dict
    :param tag_diff: dict
    :param clear_existing: bool
    :return: dict containing the tags in the state after the update.
    """
    if not tag_diff:
        return current_tags

    updated_tags = copy.deepcopy(current_tags)
    tags_to_update_boto, tags_to_remove_boto = from_diff(
        tag_diff, clear_existing=clear_existing
    )
    # TODO: we should make from_diff return dicts and convert
    # the result to boto3 notation when needed, so this can be avoided.
    tags_to_update = from_boto3(tags_to_update_boto)
    # TODO: make from_boto3 handle key-only tags
    tags_to_remove = [boto_tag['Key'] for boto_tag in tags_to_remove_boto]

    for tag in tags_to_remove:
        del updated_tags[tag]
    for tag, new_val in tags_to_update.items():
        updated_tags[tag] = new_val

    return updated_tags


def update_resource(resource, tags_to_update, tags_to_remove):
    """
    Updates the AWS resource's tags, if necessary.
    """
    # removes the tags
    if tags_to_remove:
        resource.meta.client.delete_tags(
            Resources=[resource.id],
            Tags=tags_to_remove
        )
    # creates or updates existing tags
    if tags_to_update:
        resource.meta.client.create_tags(
            Resources=[resource.id],
            Tags=tags_to_update
        )
