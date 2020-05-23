# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.


from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import ABCMeta, abstractmethod
import copy
import functools

from ansible.module_utils.six import with_metaclass

from ansible_collections.steampunk.aws.plugins.module_utils import errors


class ContainerMergeMode:
    MERGE = "merge"
    OVERRIDE = "override"


@functools.total_ordering
class ModuleEntity(with_metaclass(ABCMeta, object)):
    """
    A soft constraint imposed on subclasses is that all their member variables are assigned
    through identically-named constructor variables, and that the constructor accepts
    an extra "merge_modes" variable.
    """
    PROPERTY_PLACEHOLDER = "generated-by-aws"

    def __init__(self, merge_modes):
        """
        :param merge_modes: A mapping of property names to merge modes, used to determine whether
                            the parameters' values override or merge with existing values.
        :type merge_modes: typing.Dict[str, str]
        """
        super(ModuleEntity, self).__init__()
        self._merge_modes = merge_modes

    def __eq__(self, other):
        """Performs a per-member comparison."""
        if type(self) != type(other) or other is None:
            return False

        var_names = vars(self).keys()
        left_values = [getattr(self, v) for v in var_names]
        right_values = [getattr(other, v) for v in var_names]
        for left, right in zip(left_values, right_values):
            if left != right:
                return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def _numbered_comparison_builtins(cls, us, them):
        """Transforms cmp(us, them) into (-1, 0, 1)"""
        if us == them:
            return 0
        return (int(us > them) * 2) - 1

    @classmethod
    def _comparison_helper(cls, us, them):
        """
        Rich comparison:
            - -1 -> us < them
            - 0 -> us == them
            - 1 -< us > them
        """
        # nulls are less than everything, except other nulls, which are equal
        if us is None and them is None:
            return 0
        elif us is None and them is not None:
            return -1
        elif us is not None and them is None:
            return 1

        # assertion: us and other are not None
        if isinstance(us, list):
            if len(us) != len(them):
                return cls._numbered_comparison_builtins(len(us), len(them))
            for left, right in zip(us, them):
                cmp = cls._numbered_comparison_builtins(left, right)
                if cmp != 0:
                    return cmp

        elif isinstance(us, dict):
            if len(us) != len(them):
                return cls._numbered_comparison_builtins(len(us), len(them))
            us_keys = sorted(us.keys())
            them_keys = sorted(them.keys())
            for left_key, right_key in zip(us_keys, them_keys):
                if left_key != right_key:
                    return cls._numbered_comparison_builtins(left_key, right_key)
                left = us[left_key]
                right = us[right_key]
                cmp = cls._numbered_comparison_builtins(left, right)
                if cmp != 0:
                    return cmp

        elif isinstance(us, ModuleEntity):
            member_names = sorted(vars(us).keys())
            for member in member_names:
                left = getattr(us, member)
                right = getattr(them, member)
                comparison = cls._comparison_helper(left, right)
                if comparison != 0:
                    return comparison

        # includes string, int, and everything else
        else:
            if us != them:
                cmp = cls._numbered_comparison_builtins(us, them)
                if cmp != 0:
                    return cmp
        return 0

    def __lt__(self, other):
        """Maintains an internally-consistent sorting order.

        The sort order computation priority is based on instance member names, ascending.
        Each value is then evaluated until a difference is found.
        Types of member property values are handled as such:
          - nulls are less than everything, except nulls.
          - strings and ints are compared directly
          - lists are compared by size, then sequentially by member if sizes equal
          - dicts are compared with the same rules as ModuleEntity instances,
            but instead of member properties we have keys and their values.
          - instances of ModuleEntity are compared my member properties, then recursively
          - other types are optimistically attempted to be compared with their __lt__ methods

        With this implemented, instances are sortable using python's standard sorting mechanisms.
        functools.total_ordering, as a class decorator, implements all other comparison operations
        for free. It also requires __eq__ to be implemented.

        :type other: ModuleEntity
        :rtype: bool
        """
        if other is None:
            return False
        if type(self) != type(other) or other is None:
            raise AssertionError("Comparing instances of different classes is not allowed: "
                                 "{0} < {1}".format(type(self), type(other)))
        return self._comparison_helper(self, other) < 0

    def __str__(self):
        return "{0}({1})".format(self.__class__.__name__,
                                 ", ".join("{0}={1}".format(k, str(v))
                                           for k, v in vars(self).items()))

    def __repr__(self):
        return str(self)

    @classmethod
    @abstractmethod
    def from_boto_dict(cls, boto_dict):
        """Build a new entity from a boto metadata dictionary."""

    @classmethod
    @abstractmethod
    def from_module_params(cls, module_params):
        """Build a new entity from module parameters."""

    @abstractmethod
    def to_module_return(self):
        """Transform into the module specification."""

    @classmethod
    @abstractmethod
    def properties_modify_prohibited(cls):
        """Properties of this entity that must not be modified.

        Examples are attributes that cannot be changed, such as the description of a security group.

        :rtype: typing.Set[str]
        """

    @classmethod
    @abstractmethod
    def properties_modify_noop(cls):
        """Properties of this entity that can not be modified.

        Examples are values computed by AWS such the primary identifier or a MAC address.

        :rtype: typing.Set[str]
        """

    @abstractmethod
    def _fill_placeholders(self):
        """Fill variables that are computed remotely with placeholders or presumable defaults."""
        pass

    @classmethod
    def _get_common_vars(cls, left, right, include_private=False):
        """Return a list of common variables, taking into account ModuleEntityUnit.

        :type left: ModuleEntity
        :type right: ModuleEntity
        :rtype: typing.List[str]
        """
        if isinstance(left, ModuleEntityUnit):
            all_vars = vars(right)
        else:
            all_vars = vars(left)

        if include_private:
            return all_vars.keys()
        return [v for v in all_vars.keys() if not v.startswith("_")]

    def build_desired_state_with_params(self, params_entity):
        """Build the final requested state.

        Builds the state from this object (the initial state) and the modifications (parameters).
        Values that are None are ignored as updates.

        :type params_entity: ModuleEntity
        :return: a copy of this entity with the requested modifications.
        :rtype: ModuleEntity
        """
        nonprivate_vars = ModuleEntity._get_common_vars(self, params_entity)
        constructor_args = {"merge_modes": {}}
        for v in nonprivate_vars:
            value_before = getattr(self, v, None)
            value_after = getattr(params_entity, v, None)

            if value_before is None:
                # no other choice
                constructor_args[v] = value_after
            elif value_after is None:
                # don't update, as clears et al happen with empty lists
                constructor_args[v] = value_before
            elif isinstance(value_after, ModuleEntity):
                constructor_args[v] = value_before.build_desired_state_with_params(value_after)
            elif isinstance(value_after, list):
                if params_entity._merge_modes[v] == ContainerMergeMode.OVERRIDE:
                    constructor_args[v] = value_after
                else:
                    new_elements = set(value_before)
                    new_elements.update(set(value_after))
                    constructor_args[v] = list(new_elements)
            elif isinstance(value_after, dict):
                if params_entity._merge_modes[v] == ContainerMergeMode.OVERRIDE:
                    constructor_args[v] = value_after
                else:
                    new_dict = copy.deepcopy(value_before)
                    new_dict.update(value_after)
                    constructor_args[v] = new_dict
            else:
                constructor_args[v] = value_after

        if isinstance(self, ModuleEntityUnit):
            constructor = params_entity.__class__
        else:
            constructor = self.__class__
        return constructor(**constructor_args)

    @classmethod
    def _attributes_differ(cls, us, them, strict_list_order):
        # special processing for special cases
        if us is not None and them is not None:
            if isinstance(us, ModuleEntity) and us.differing_properties_to(them):
                return True
            elif isinstance(us, list):
                if not strict_list_order:
                    return set(us) != set(them)
        return us != them

    def differing_properties_to(self, other, return_noops=False, strict_list_order=False):
        """Returns properties that differ between this and other.

        Non-strict list ordering only works for items that are hashable.

        :type other: ModuleEntity
        :param return_noops: if False, this does not return properties with modifications
                             specified as noops in self.properties_modify_noop().
        :type return_noops: bool
        :param strict_list_order: if True, lists are compared as ordered,
                                  otherwise order does not matter
        :type strict_list_order: bool
        :rtype: typing.Set[str]
        """
        differing = set()
        nonprivate_vars = ModuleEntity._get_common_vars(self, other)
        for prop in nonprivate_vars:
            us = getattr(self, prop, None)
            them = getattr(other, prop, None)
            if ModuleEntity._attributes_differ(us, them, strict_list_order):
                differing.add(prop)

        if return_noops:
            return differing
        else:
            return differing - self.properties_modify_noop()

    def deepcopy(self):
        """
        :rtype: ModuleEntity
        """
        all_vars = ModuleEntity._get_common_vars(self, self)
        constructor_args = dict(merge_modes=self._merge_modes)
        for name in all_vars:
            val = getattr(self, name)
            if isinstance(val, ModuleEntity):
                constructor_args[name] = val.deepcopy()
            else:
                constructor_args[name] = copy.deepcopy(val)
        return self.__class__(**constructor_args)

    def with_placeholders(self):
        dupe = self.deepcopy()
        dupe._fill_placeholders()
        return dupe

    @classmethod
    def validate_prohibited_differing_properties(cls, props):
        """Validates permitted changes between two entities.

        :type props: typing.Iterable[str]
        :raises errors.ValidationError: when a diff validation fails.
        """
        modified_but_prohibited = set(props).intersection(cls.properties_modify_prohibited())
        if modified_but_prohibited:
            raise errors.ValidationError("Cannot update property: "
                                         "{0}".format(", ".join(modified_but_prohibited)))

    def ansible_diff_to(self, other):
        """
        :type other: ModuleEntity
        :rtype: typing.Dict[typing.Literal["before", "after"], dict]
        """
        return {"before": self.to_module_return(), "after": other.to_module_return()}


class ModuleEntityUnit(ModuleEntity):
    """The unit for paired ModuleEntity operations."""
    def __init__(self, merge_modes=None):
        super(ModuleEntityUnit, self).__init__(merge_modes or {})

    @classmethod
    def from_boto_dict(cls, boto_dict):
        raise AssertionError("The unit can not be constructed from a boto dict.")

    @classmethod
    def from_module_params(cls, module_params):
        raise AssertionError("The unit can not be constructed from module parameters.")

    def to_module_return(self):
        return {}

    @classmethod
    def properties_modify_prohibited(cls):
        return frozenset()

    @classmethod
    def properties_modify_noop(cls):
        return frozenset()

    def _fill_placeholders(self):
        pass
