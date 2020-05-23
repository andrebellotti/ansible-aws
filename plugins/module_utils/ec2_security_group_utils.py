# -*- coding: utf-8 -*-
#
# Copyright 2020 XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import itertools

from ansible.module_utils import six
from ansible.module_utils.compat import ipaddress

from ansible_collections.steampunk.aws.plugins.module_utils import ec2_filters, tag_utils


def get_default_security_group_for_vpc(ec2, vpc_id):
    secgroups = list(ec2.security_groups.filter(
        Filters=ec2_filters.from_dict({"vpc-id": vpc_id, "group-name": "default"})
    ))
    # there is exactly one secgroup that matches this filter, it can't be deleted
    sg = secgroups[0]
    sg.load()
    return sg


def security_group_exists(ec2, secgroup_id):
    # noinspection PyBroadException
    try:
        sg = ec2.SecurityGroup(secgroup_id)
        sg.load()
        return True
    except Exception:
        return False


def security_group_in_vpc(ec2, secgroup_id, vpc_id):
    # noinspection PyBroadException
    try:
        sg = ec2.SecurityGroup(secgroup_id)
        sg.load()
    except Exception:
        return False
    return sg.vpc_id == vpc_id


def boto_dict_to_module_return(boto_dict):
    """
    :type boto_dict: dict
    :rtype: dict
    """
    ingress_lol = [SimpleSecurityGroupRule.from_boto_dict("ingress", rule_dict)
                   for rule_dict in boto_dict["IpPermissions"]]
    egress_lol = [SimpleSecurityGroupRule.from_boto_dict("egress", rule_dict)
                  for rule_dict in boto_dict["IpPermissionsEgress"]]
    ingress = list(itertools.chain(*ingress_lol))
    egress = list(itertools.chain(*egress_lol))

    return dict(
        id=boto_dict["GroupId"],
        name=boto_dict["GroupName"],
        vpc=boto_dict["VpcId"],
        description=boto_dict["Description"],
        tags=tag_utils.from_boto3(boto_dict.get("Tags", [])),
        ingress=dict(rules=[r.to_module_return() for r in ingress]),
        egress=dict(rules=[r.to_module_return() for r in egress])
    )


class _ComparisonState:
    EQUAL = "equal"
    UPDATE = "update"
    NO_MATCH = "no-match"


class IpRange:
    def __init__(self, cidr, description=None):
        self.cidr = cidr
        self.description = description

    @classmethod
    def from_module_params(cls, params_dict):
        return cls(
            cidr=params_dict["cidr"],
            description=params_dict.get("description")
        )

    @classmethod
    def from_boto_dict(cls, boto_dict):
        return cls(
            cidr=boto_dict.get("CidrIp") or boto_dict["CidrIpv6"],
            description=boto_dict.get("Description")
        )

    def to_module_return(self):
        return dict(cidr=self.cidr, description=self.description)

    def to_boto_dict(self):
        result = dict()
        if self.is_ipv4:
            result["CidrIp"] = self.cidr
        else:
            result["CidrIpv6"] = self.cidr
        if self.description is not None:
            result["Description"] = self.description
        return result

    def normalize(self):
        """Normalizes a CIDR descriptor, e.g. 1.2.3.4/5 == 0.0.0.0/5."""
        # ipaddress is picky and needs inputs to be unicode, i.e. not bytes==str in py2
        normalized_cidr = ipaddress.ip_network(six.u(self.cidr), strict=False).compressed
        return self.__class__(cidr=normalized_cidr, description=self.description)

    @property
    def is_ipv4(self):
        # assumes cidr validity
        return ":" not in self.cidr

    def compare_to(self, other):
        """
        :type other: IpRange
        :return: _ComparisonState
        :rtype: str
        """
        if self.cidr == other.cidr:
            if self.description == other.description:
                return _ComparisonState.EQUAL
            return _ComparisonState.UPDATE
        return _ComparisonState.NO_MATCH

    def __str__(self):
        return "IpRange({0}, {1})".format(self.cidr, self.description)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return isinstance(other, IpRange) and self.compare_to(other) == _ComparisonState.EQUAL

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.cidr, self.description))


class SecurityGroupDescriptionPair:
    SECURITY_GROUP_SELF_REFERENCE = "self"
    """References "this" security group."""

    def __init__(self, security_group_id, description=None):
        self.security_group_id = security_group_id
        self.description = description

    @classmethod
    def from_module_params(cls, params_dict):
        return cls(
            security_group_id=params_dict["id"],
            description=params_dict.get("description")
        )

    @classmethod
    def from_boto_dict(cls, boto_dict):
        return cls(
            security_group_id=boto_dict["GroupId"],
            description=boto_dict.get("Description")
        )

    def to_module_return(self):
        return dict(id=self.security_group_id, description=self.description)

    def to_boto_dict(self):
        result = dict(GroupId=self.security_group_id)
        if self.description is not None:
            result["Description"] = self.description
        return result

    def render_loopback_reference(self, loopback_security_group_id):
        if self.security_group_id == self.SECURITY_GROUP_SELF_REFERENCE:
            sgid = loopback_security_group_id
        else:
            sgid = self.security_group_id

        return self.__class__(
            security_group_id=sgid,
            description=self.description
        )

    def compare_to(self, other):
        """
        :type other: SecurityGroupDescriptionPair
        :return: _ComparisonState
        :rtype: str
        """
        if self.security_group_id == other.security_group_id:
            if self.description == other.description:
                return _ComparisonState.EQUAL
            else:
                return _ComparisonState.UPDATE
        else:
            return _ComparisonState.NO_MATCH

    def __str__(self):
        return "SecurityGroupDescriptionPair({0}, {1})".format(self.security_group_id,
                                                               self.description)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return isinstance(other, SecurityGroupDescriptionPair)\
            and self.compare_to(other) == _ComparisonState.EQUAL

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.security_group_id, self.description))


class SimpleSecurityGroupRule:
    """
    The "identifier" for a rule is (direction, protocol, port/icmp_from, port/icmp_to)

    If a rule with only a different IP range or secgroup reference is added in the AWS console,
    it's presented as the same rule but with an additional IP range in the API.

    This class is a "simple" rule without collections of IP ranges/security groups.
    It corresponds to one row in the AWS console.
    """

    def __init__(self, direction, protocol, ip_range=None, security_group=None,
                 port_from=None, port_to=None, icmp_type=None, icmp_code=None):
        """
        Performs no param validation in the sense of required_by, mutex, choices.

        :type direction: typing.Literal["ingress", "egress"]
        :type protocol: typing.Literal["all", "tcp", "udp", "icmp", "icmpv6"]
        :type ip_range: typing.Optional[IpRange]
        :type security_group: typing.Optional[SecurityGroupDescriptionPair]
        :type port_from: typing.Optional[int]
        :type port_to: typing.Optional[int]
        :type icmp_type: typing.Optional[int]
        :type icmp_code: typing.Optional[int]
        """
        self.direction = direction
        self.protocol = protocol
        self.ip_range = ip_range
        self.security_group = security_group
        self.port_from = port_from
        self.port_to = port_to
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code

    @classmethod
    def default_egress(cls):
        """Applied as a default to all security groups."""
        return cls(direction="egress", protocol="all", ip_range=IpRange(cidr="0.0.0.0/0"))

    @classmethod
    def from_module_params(cls, direction, params_dict):
        """
        :type direction: typing.Literal["ingress", "egress"]
        :type params_dict: dict
        :rtype: typing.List[SimpleSecurityGroupRule]
        """
        icmp_mode = params_dict["protocol"] in ("icmp", "icmpv6")

        param_port = params_dict.get("port")
        param_port_from = params_dict.get("port_from")
        param_port_to = params_dict.get("port_to")

        if icmp_mode:
            port_from = None
            port_to = None
            icmp_type = params_dict["icmp_type"]
            icmp_code = params_dict["icmp_code"]
        else:
            icmp_type = None
            icmp_code = None
            if param_port is not None:
                port_from = param_port
                port_to = param_port
            else:
                port_from = param_port_from
                port_to = param_port_to

        base_params = dict(
            direction=direction,
            protocol=params_dict["protocol"],
            port_from=port_from,
            port_to=port_to,
            icmp_type=icmp_type,
            icmp_code=icmp_code
        )

        result = []
        for r in [IpRange.from_module_params(d)
                  for d in params_dict.get("ip_ranges") or []]:
            result.append(cls(ip_range=r, security_group=None, **base_params))
        for sgi in [SecurityGroupDescriptionPair.from_module_params(d)
                    for d in params_dict.get("security_groups") or []]:
            result.append(cls(ip_range=None, security_group=sgi, **base_params))
        return result

    @classmethod
    def from_boto_dict(cls, direction, boto_dict):
        icmp_mode = boto_dict["IpProtocol"] in ("icmp", "icmpv6")

        if boto_dict["IpProtocol"] == "-1":
            protocol = "all"
        else:
            protocol = boto_dict["IpProtocol"]

        base_params = dict(
            direction=direction,
            protocol=protocol,
            port_from=boto_dict.get("FromPort") if not icmp_mode else None,
            port_to=boto_dict.get("ToPort") if not icmp_mode else None,
            icmp_type=boto_dict.get("FromPort") if icmp_mode else None,
            icmp_code=boto_dict.get("ToPort") if icmp_mode else None,
        )

        result = []
        for r in [IpRange.from_boto_dict(d) for d in boto_dict.get("IpRanges", [])] + \
                 [IpRange.from_boto_dict(d) for d in boto_dict.get("Ipv6Ranges", [])]:
            result.append(cls(ip_range=r, security_group=None, **base_params))
        for sgi in [SecurityGroupDescriptionPair.from_boto_dict(d)
                    for d in boto_dict.get("UserIdGroupPairs", [])]:
            result.append(cls(ip_range=None, security_group=sgi, **base_params))
        return result

    def to_module_return(self):
        ip_ranges = []
        if self.ip_range is not None:
            ip_ranges = [self.ip_range.to_module_return()]

        uigp = []
        if self.security_group is not None:
            uigp = [self.security_group.to_module_return()]

        return dict(
            protocol=self.protocol,
            port_from=self.port_from,
            port_to=self.port_to,
            icmp_type=self.icmp_type,
            icmp_code=self.icmp_code,
            ip_ranges=ip_ranges,
            security_groups=uigp,
        )

    def to_boto_dict(self):
        """Generates an IpPermission element for use in {authorize,revoke}_{ingress,egress}."""
        result = dict()

        if self.is_icmp:
            port_from = self.icmp_type
            port_to = self.icmp_code
        else:
            port_from = self.port_from
            port_to = self.port_to
        if port_from is not None:
            result["FromPort"] = port_from
        if port_to is not None:
            result["ToPort"] = port_to

        if self.protocol == "all":
            result["IpProtocol"] = "-1"
        else:
            result["IpProtocol"] = self.protocol

        if self.ip_range is not None:
            if self.ip_range.is_ipv4:
                result["IpRanges"] = [self.ip_range.to_boto_dict()]
            else:
                result["Ipv6Ranges"] = [self.ip_range.to_boto_dict()]

        if self.security_group is not None:
            result["UserIdGroupPairs"] = [self.security_group.to_boto_dict()]

        return result

    def render_loopback_reference(self, loopback_security_group_id):
        if self.security_group is not None:
            sg = self.security_group.render_loopback_reference(loopback_security_group_id)
        else:
            sg = None

        return self.__class__(
            direction=self.direction, protocol=self.protocol, ip_range=self.ip_range,
            security_group=sg, port_from=self.port_from, port_to=self.port_to,
            icmp_type=self.icmp_type, icmp_code=self.icmp_code,
        )

    def normalize_ip_range(self):
        if self.ip_range is not None:
            ir = self.ip_range.normalize()
        else:
            ir = None

        return self.__class__(
            direction=self.direction, protocol=self.protocol, ip_range=ir,
            security_group=self.security_group, port_from=self.port_from, port_to=self.port_to,
            icmp_type=self.icmp_type, icmp_code=self.icmp_code,
        )

    @property
    def is_icmp(self):
        return self.protocol in ("icmp", "icmpv6")

    def __str__(self):
        return "SimpleSecurityGroupRule({0})" \
            .format(", ".join(str(el) for el in (self.direction, self.protocol, self.ip_range,
                                                 self.security_group, self.port_from, self.port_to,
                                                 self.icmp_type, self.icmp_code)))

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return isinstance(other, SimpleSecurityGroupRule) \
            and self.compare_to(other) == _ComparisonState.EQUAL

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.direction, self.protocol, self.ip_range, self.security_group,
                     self.port_from, self.port_to, self.icmp_type, self.icmp_code))

    def compare_to(self, other):
        """
        :type other: SimpleSecurityGroupRule
        :return: _ComparisonState
        :rtype: str
        """
        # check whether we match with the grouping identifiers
        if self.direction == other.direction \
                and self.protocol == other.protocol \
                and (
                (self.is_icmp
                 and self.icmp_type == other.icmp_type
                 and self.icmp_code == other.icmp_code)
                or (not self.is_icmp
                    and self.port_from == other.port_from
                    and self.port_to == other.port_to)):

            # exactly one of these two is not None because they are exclusive when parsing
            ip_range_comparison = None \
                if self.ip_range is None or other.ip_range is None \
                else self.ip_range.compare_to(other.ip_range)
            security_group_comparison = None \
                if self.security_group is None or other.security_group is None \
                else self.security_group.compare_to(other.security_group)

            if ip_range_comparison == _ComparisonState.EQUAL or \
                    security_group_comparison == _ComparisonState.EQUAL:
                # if we also match on either the IP range or secgroup (exclusive when parsing),
                # we are exactly the same rule
                return _ComparisonState.EQUAL
            else:
                if ip_range_comparison == _ComparisonState.UPDATE or \
                        security_group_comparison == _ComparisonState.UPDATE:
                    return _ComparisonState.UPDATE
                else:
                    # otherwise we don't have an anchor point (cidr, secgroup) to update,
                    # and we don't match
                    return _ComparisonState.NO_MATCH
        else:
            return _ComparisonState.NO_MATCH

    @classmethod
    def get_rule_diff(cls, existing_rules, desired_rules, desired_are_authoritative):
        """
        :type existing_rules: typing.List[SimpleSecurityGroupRule]
        :type desired_rules: typing.List[SimpleSecurityGroupRule]
        :type desired_are_authoritative: bool
        :return: (create, (update_existing, update_desired), delete, unchanged)
        :rtype: typing.Tuple[
                    typing.List[SimpleSecurityGroupRule],
                    typing.List[typing.Tuple[SimpleSecurityGroupRule, SimpleSecurityGroupRule]],
                    typing.List[SimpleSecurityGroupRule],
                    typing.List[SimpleSecurityGroupRule]
                ]
        """
        create = []
        update = []
        delete = []
        unchanged = []

        processed_existing_rules = []
        for desired in desired_rules:
            comparisons = sorted(
                [(existing.compare_to(desired), existing) for existing in existing_rules],
                key=lambda c: c[0]
            )
            comparison_groups = {group: [tup[1] for tup in list(k_existing_tuples)]
                                 for group, k_existing_tuples
                                 in itertools.groupby(comparisons, key=lambda c: c[0])}

            existing_equal = comparison_groups.get(_ComparisonState.EQUAL, [])
            existing_update = comparison_groups.get(_ComparisonState.UPDATE, [])

            # we can have at most 1 equal rule or 1 update rule
            # otherwise our grouping/equals logic is faulty or there is something wrong with
            # our assumptions of aws behaviour
            if len(existing_equal) > 1 or len(existing_update) > 1:
                raise AssertionError("Bug guard: rule grouping assertion is wrong.")

            # if the only matches are no matches, we create the desired rule
            if not existing_equal and not existing_update:
                create.append(desired)
            elif existing_equal:
                processed_existing_rules.append(existing_equal[0])
                unchanged.append(desired)
            else:
                # == elif existing_update
                processed_existing_rules.append(existing_update[0])
                update.append((existing_update[0], desired))

        # any rule that is left over is either unchanged if we don't treat desired as authoritative
        # or is deleted if the desired rules are the only ones we want to keep
        unprocessed_existing_rules = set(existing_rules) - set(processed_existing_rules)
        if desired_are_authoritative:
            delete.extend(unprocessed_existing_rules)
        else:
            unchanged.extend(unprocessed_existing_rules)

        return create, update, delete, unchanged
