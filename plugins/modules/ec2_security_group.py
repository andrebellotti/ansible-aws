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
module: ec2_security_group
author:
  - Manca Bizjak (@mancabizjak)
  - Aljaz Kosir (@aljazkosir)
  - Saso Stanovnik (@sstanovnik)
  - Miha Dolinar (@mdolinar)
  - Tadej Borovsak (@tadeboro)
short_description: Manage EC2 VPC security groups.
description:
  - Create, delete or update an EC2 VPC security group.
extends_documentation_fragment:
  - steampunk.aws.auth
  - steampunk.aws.tags
  - steampunk.aws.clear_tags
  - steampunk.aws.description
  - steampunk.aws.id
options:
  name:
    description:
      - The name for the security group.
      - Required when creating a security group or in combination with I(vpc) to uniquely
        identify one.
      - Note that the security group name is not an AWS resource tag.
    type: str
  vpc:
    description:
      - The ID of the VPC to assign this security group to.
      - If omitted, the default VPC is assumed.
      - When I(id) is not specified, I(vpc) will be used to identify a single security group
        in combination with I(name).
    type: str
  state:
    description:
      - The desired state of the security group.
      - If C(absent), the security group is first detached from any instances and then deleted.
    type: str
    choices: [present, absent]
    default: present
  ingress:
    description:
      - Ingress (inbound) security rules.
      - Note that AWS creates a default ingress rule, which allows all traffic from the same
        security group, but only in the default security group created when a VPC is created.
    type: dict
    suboptions: &gress_suboptions
      clear_rules:
        description:
          - Whether to clear rules not specified in the I(rules) section.
          - In other words, whether to treat the rule definitions of this task as exclusive.
        type: bool
        default: false
      rules:
        description:
          - IP/ICMP filtering rules as a whitelist.
          - The default value for this module does not include includes the default rules
            AWS creates. When clearing all rules, take note that the rules created by default will
            also be cleared.
        type: list
        elements: dict
        suboptions:
          protocol:
            description:
              - What protocol this rule applies to.
            required: true
            type: str
            choices: [all, tcp, udp, icmp, icmpv6]
          port_from:
            description:
              - The start port (inclusive) of the port range of this rule.
              - Only used when I(protocol=[tcp, udp])
              - Mutually exclusive with I(port).
              - Requires I(port_to).
            required: false
            type: int
          port_to:
            description:
              - The start port (inclusive) of the port range of this rule.
              - Only used when I(protocol=[tcp, udp])
              - Mutually exclusive with I(port).
              - Requires I(port_from).
            required: false
            type: int
          port:
            description:
              - The port specification for this rule.
              - Only used when I(protocol=[tcp, udp])
              - Mutually exclusive with I(port_from) and I(port_to).
            required: false
            type: int
            default:
          icmp_type:
            description:
              - The ICMP type for this rule. If this parameter is omitted, the default
                behaviour is to allow all ICMP types.
              - Only used when I(protocol=[icmp, icmpv6])
              - If specifying I(icmp_code), this parameter is required.
            required: false
            type: int
          icmp_code:
            description:
              - The ICMP code (subtype) for this rule. If this parameter is omitted, the default
                behaviour is to allow all ICMP codes.
              - Only used when I(protocol=[icmp, icmpv6])
              - When I(icmp_code) is specified, I(icmp_type) is required.
            required: false
            type: int
          security_groups:
            description:
              - The security group IDs when using VPC peering.
              - A special ID value of C(self) references the security group controlled by this task.
            type: list
            elements: dict
            suboptions:
              id:
                description:
                  - The ID of the security group this rule references.
                required: true
                type: str
              description:
                description:
                  - An optional description for this security group reference.
                type: str
          ip_ranges:
            description:
              - The IP ranges for this rule in CIDR notation.
            type: list
            elements: dict
            suboptions:
              cidr:
                description:
                  - In CIDR notation, the IP range of this rule.
                required: true
                type: str
              description:
                description:
                  - An optional description for this IP range.
                required: false
                type: str
  egress:
    description:
      - Egress (outbound) security rules.
      - Note that by default, every newly created security group will include a default egress
        rule which permits all outbound traffic.
    type: dict
    suboptions: *gress_suboptions

seealso:
  - module: ec2_security_group_info
"""

# language=yaml
EXAMPLES = """
- name: Create a very simple security group in the default vpc,
        allows all outbound and internal traffic
  ec2_security_group:
    name: my-first-security
    description: Secure me.
  register: first_security

- name: Prohibit all egress traffic from the security group
  ec2_security_group:
    id: "{{ first_security['GroupId'] }}"
    egress:
      rules: []
      clear_rules: true

- name: Prohibit internal traffic within the security group
  ec2_security_group:
    id: "{{ first_security['GroupId'] }}"
    ingress:
      rules: []
      clear_rules: true

- name: Allow unidirectional cross-traffic between this and another security group
  ec2_security_group:
    id: "{{ first_security['GroupId'] }}"
    egress:
      rules:
        - protocol: all
          security_groups:
            - id: sg-1

- name: Allow IPv6-only 80/tcp, ICMPv4 and ICMPv6 echo traffic to the security group
  ec2_security_group:
    id: "{{ first_security['GroupId'] }}"
    ingress:
      rules:
        - protocol: tcp
          port: 80
          ip_ranges:
            - cidr: ::/0
        - protocol: udp
          port_from: 10000
          port_to: 10010
          ip_ranges:
            - cidr: 192.0.2.0/24
              description: Super Load Balancer 3000
        - protocol: icmp
          icmp_type: 8
          ip_ranges:
            - cidr: 0.0.0.0/0
        - protocol: icmpv6
          icmp_type: 8
          ip_ranges:
            - cidr: 0.0.0.0/0

- name: Remove a security group
  ec2_security_group:
    id: "{{ first_security['GroupId'] }}"
    state: absent
"""

# language=yaml
RETURN = """
object:
  description: An object representing an EC2 VPC security group.
  returned: success and I(state=present)
  type: dict
  contains:
    id:
      description: The ID of the security group.
      type: str
      returned: always
    name:
      description: The name of the security group.
      type: str
      returned: always
    vpc:
      description: The ID of the VPC this security group is assigned to.
      type: str
      returned: always
    description:
      description: The security group's description.
      type: str
      returned: always
    tags:
      description: The tags assigned to this security group.
      type: dict
      returned: always
    ingress:
      description: Ingress (inbound) security rules.
      type: dict
      returned: always
      contains:
        rules:
          description:
            - Ingress (inbound) security rules.
            - Rules are normalized so each rule only contains one of I(security_groups) or
              I(ip_ranges), and at most one element.
          type: list
          returned: always
          contains: &gress_suboptions
            protocol:
              description: The protocol this rule applies to.
              type: str
              returned: always
            port_from:
              description: The start port (inclusive) of the port range of this rule.
              type: int
              returned: when I(protocol=[tcp, udp])
            port_to:
              description: The start port (inclusive) of the port range of this rule.
              type: int
              returned: when I(protocol=[tcp, udp])
            icmp_type:
              description: The ICMP type for this rule.
              type: int
              returned: when I(protocol=[icmp, icmpv6])
            icmp_code:
              description: The ICMP code (subtype) for this rule.
              type: int
              returned: when I(protocol=[icmp, icmpv6])
            security_groups:
              description: A list of a single security group ID and its description.
              type: list
              returned: when I(ip_range) is not present
              contains:
                id:
                  description: The ID of the security group this rule references.
                  type: str
                  returned: always
                description:
                  description: The description for this security group reference, if any.
                  type: str
            ip_ranges:
              description: A list of a single IP range for this rule in CIDR notation.
              type: list
              returned: when I(security_group) is not present
              contains:
                cidr:
                  description: In CIDR notation, the IP range of this rule.
                  returned: always
                  type: str
                description:
                  description: An optional description for this IP range.
                  type: str
    egress:
      description: Egress (outbound) security rules.
      type: dict
      returned: always
      contains:
        rules:
          description:
            - Egress (outbound) security rules.
            - Rules are normalized so each rule only contains one of I(security_groups) or
              I(ip_ranges), and at most one element.
          type: list
          returned: always
          contains: *gress_suboptions
  sample:
    object:
      id: sg-df1b2aa66
      name: my-first-secgroup
      vpc: vpc-faff5721
      description: A description for my first security group.
      tags:
        MyCompany-Department: legal
      ingress:
        rules:
          - protocol: tcp
            port_from: 22
            port_to: 22
            ip_ranges:
              - cidr: 0.0.0.0/0
                description: the world
      egress:
        rules:
          - protocol: icmp
            icmp_type: 8
            icmp_code: 0
            security_groups:
              - id: sg-64508346
                description: local sonar
"""

import itertools

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.steampunk.aws.plugins.module_utils import (
    spec, boto, ec2_filters, errors, tag_utils, ec2_vpc_utils
)
from ansible_collections.steampunk.aws.plugins.module_utils.ec2_security_group_utils import \
    SimpleSecurityGroupRule, boto_dict_to_module_return


def _custom_validation_fromto_validity_single_criteria(gress_type, rule_index, rule_dict):
    errors = []
    for fromto in ("from", "to"):
        if rule_dict.get("port_{0}".format(fromto)) is not None \
                and rule_dict.get("port") is not None:
            errors.append("{0}.rules[{2}].port_{1} is mutually exclusive with "
                          "{0}.rules[{2}].port".format(gress_type, fromto, rule_index))
    return errors


def _custom_validation_fromto_validity_combined_criteria(gress_type, rule_index, rule_dict):
    errors = []
    for a, b in (("from", "to"), ("to", "from")):
        if rule_dict.get("port_{0}".format(a)) is not None \
                and rule_dict.get("port_{0}".format(b)) is None:
            errors.append("{0}.rules[{1}].port_{2} requires "
                          "{0}.rules[{1}].port_{3} to be specified".format(gress_type,
                                                                           rule_index, a, b))
    return errors


def _custom_validation_fromto_validity(gress_type, rule_index, rule_dict):
    errors = []
    errors.extend(_custom_validation_fromto_validity_single_criteria(gress_type,
                                                                     rule_index,
                                                                     rule_dict))
    errors.extend(_custom_validation_fromto_validity_combined_criteria(gress_type,
                                                                       rule_index,
                                                                       rule_dict))
    return errors


def _custom_validation_protocol_requirements_tcp_udp(gress_type, rule_index, rule_dict):
    errors = []
    for fromto in ("from", "to"):
        if rule_dict.get("port_{0}".format(fromto)) is not None \
                and rule_dict["protocol"] not in ("tcp", "udp"):
            errors.append("{0}.rules[{2}].port_{1} can only be specified when "
                          "{0}.rules[{2}].protocol is in "
                          "(tcp, udp)".format(gress_type, fromto, rule_index))

    if rule_dict.get("port") is not None and rule_dict["protocol"] not in ("tcp", "udp"):
        errors.append("{0}.rules[{1}].port can only be specified when "
                      "{0}.rules[{1}].protocol is in (tcp, udp)".format(gress_type,
                                                                        rule_index))
    return errors


def _custom_validation_protocol_requirements_icmp_icmpv6(gress_type, rule_index, rule_dict):
    errors = []
    for icmp_thing in ("type", "code"):
        if rule_dict.get("icmp_{0}".format(icmp_thing)) is not None \
                and rule_dict["protocol"] not in ("icmp", "icmpv6"):
            errors.append("{0}.rules[{2}].icmp_{1} can only be specified when "
                          "{0}.rules[{2}].protocol is in "
                          "(tcp, udp)".format(gress_type, icmp_thing, rule_index))
    return errors


def _custom_validation_protocol_requirements(gress_type, rule_index, rule_dict):
    errors = []
    errors.extend(_custom_validation_protocol_requirements_tcp_udp(gress_type,
                                                                   rule_index,
                                                                   rule_dict))
    errors.extend(_custom_validation_protocol_requirements_icmp_icmpv6(gress_type,
                                                                       rule_index,
                                                                       rule_dict))
    return errors


def _custom_validation_icmp_nested_requirement(rule_dict):
    errors = []
    if rule_dict.get("icmp_code") is not None and not rule_dict.get("icmp_type") is not None:
        errors.append("when specifying icmp_code, icmp_type is required")
    return errors


def _custom_validation_rule_mutual_exclusivity(gress_type, rule_index, rule_dict):
    errors = []
    if not rule_dict.get("ip_ranges", []) and not rule_dict.get("security_groups", []):
        errors.append("{0}.rules[{1}]: at least one of (ip_ranges, security_groups) "
                      "must be specified".format(gress_type, rule_index))
    return errors


def _custom_validation_rule(gress_type, rule_index, rule_dict):
    errors = []
    errors.extend(_custom_validation_fromto_validity(gress_type, rule_index, rule_dict))
    errors.extend(_custom_validation_protocol_requirements(gress_type, rule_index, rule_dict))
    errors.extend(_custom_validation_icmp_nested_requirement(rule_dict))
    errors.extend(_custom_validation_rule_mutual_exclusivity(gress_type, rule_index, rule_dict))
    return errors


def _custom_validation_gress(gress_type, gress_subdict):
    errors = []
    for rule_index, rule_dict in enumerate(gress_subdict.get("rules", [])):
        errors.extend(_custom_validation_rule(gress_type, rule_index, rule_dict))
    return errors


def do_custom_validation(params):
    """
    :type params: dict
    :rtype: typing.List[str]
    """
    errors = []
    for gress_type in ("ingress", "egress"):
        if gress_type in params and params[gress_type]:
            errors.extend(_custom_validation_gress(gress_type, params[gress_type]))
    return errors


def _get_existing_secgroup_by_id(ec2, secgroup_id):
    try:
        secgroup = ec2.SecurityGroup(secgroup_id)
        secgroup.load()
        return secgroup
    except boto.ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound" \
                or e.response["Error"]["Code"] == "InvalidGroupId.Malformed":
            return None
        raise


def _get_existing_secgroup_by_name_and_vpc(ec2, name, vpc_id):
    # errors out when this does not exist
    # prevents boto.ClientError.response["Error"]["Code"] == "InvalidParameterValue" below
    vpc = ec2_vpc_utils.get_vpc(ec2, vpc_id)
    secgroups = list(vpc.security_groups.filter(
        Filters=ec2_filters.from_dict({"group-name": name})
    ))

    if len(secgroups) == 0:
        return None
    elif len(secgroups) == 1:
        return secgroups[0]

    raise errors.AmbiguousObjectError("More than one security group with the name '{0}' "
                                      "exists in VPC {1}".format(name, vpc_id))


def _apply_ruleset_changes(sg, direction, existing, requested, clear_rules, check_mode):
    """
    :return: changed
    :rtype: bool
    """
    create, update, delete, unchanged = \
        SimpleSecurityGroupRule.get_rule_diff(existing, requested, clear_rules)

    # aws doesn't update, so updates are delete+create
    delete_botos = [rule.to_boto_dict()
                    for rule in itertools.chain(delete, (tup[0] for tup in update))]
    create_botos = [rule.to_boto_dict()
                    for rule in itertools.chain(create, (tup[1] for tup in update))]

    if direction == "ingress":
        auth = sg.authorize_ingress
        deauth = sg.revoke_ingress
    else:
        # direction == "egress"
        auth = sg.authorize_egress
        deauth = sg.revoke_egress

    if not check_mode:
        if delete_botos:
            deauth(IpPermissions=delete_botos)
        if create_botos:
            auth(IpPermissions=create_botos)

    return bool(create or update or delete)


def _get_or_create(ec2, module_params, check_mode):
    vpc_id = module_params["vpc"]
    changed = False
    if module_params["id"]:
        sg = _get_existing_secgroup_by_id(ec2, module_params["id"])
        if sg is None:
            raise errors.ObjectDoesNotExist("The security group with id '{0}' does not exist."
                                            .format(module_params["id"]))
    else:
        # for non-id identification or not-found creation, we default to the default vpc
        if vpc_id is None:
            default_vpc = ec2_vpc_utils.get_default_vpc(ec2)
            vpc_id = default_vpc.id

        sg = _get_existing_secgroup_by_name_and_vpc(ec2, module_params["name"], vpc_id)
        if sg is None:
            changed = True

            if module_params["description"] is None:
                raise errors.ValidationError("When creating a security group, "
                                             "a description is required.")

            if check_mode:
                # we stop here, because we don't want to simulate all operations
                # on a virtual security group if we know the result already
                return changed, dict(
                    GroupId="generated-by-aws", VpcId=vpc_id, GroupName=module_params["name"],
                    Description=module_params["description"], Tags=[], IpPermissions=[],
                    IpPermissionsEgress=[SimpleSecurityGroupRule.default_egress().to_boto_dict()]
                )
            sg = ec2.create_security_group(VpcId=vpc_id,
                                           GroupName=module_params["name"],
                                           Description=module_params["description"])
            waiter = ec2.meta.client.get_waiter("security_group_exists")
            waiter.wait(GroupIds=[sg.id])
    return changed, sg


def _update(sg, module_params, check_mode):
    changed = False
    if module_params["tags"]:
        tag_diff = tag_utils.get_diff(module_params["name"], module_params["tags"],
                                      tag_utils.from_boto3(sg.tags or []))
        tag_update, tag_remove = tag_utils.from_diff(tag_diff, module_params["clear_tags"])
        changed |= bool(tag_update) or bool(tag_remove)
        if not check_mode:
            tag_utils.update_resource(sg, tag_update, tag_remove)

    request_ingress_rules = [r.render_loopback_reference(sg.id).normalize_ip_range()
                             for r in itertools.chain.from_iterable(
        SimpleSecurityGroupRule.from_module_params("ingress", d)
        for d in module_params["ingress"].get("rules", [])
    )]
    request_egress_rules = [r.render_loopback_reference(sg.id).normalize_ip_range()
                            for r in itertools.chain.from_iterable(
        SimpleSecurityGroupRule.from_module_params("egress", d)
        for d in module_params["egress"].get("rules", [])
    )]

    existing_ingress_rules = list(itertools.chain.from_iterable(
        SimpleSecurityGroupRule.from_boto_dict("ingress", d) for d in sg.ip_permissions
    ))
    existing_egress_rules = list(itertools.chain.from_iterable(
        SimpleSecurityGroupRule.from_boto_dict("egress", d) for d in sg.ip_permissions_egress
    ))

    changed |= _apply_ruleset_changes(sg, "ingress",
                                      existing_ingress_rules, request_ingress_rules,
                                      module_params["ingress"].get("clear_rules", False),
                                      check_mode)
    changed |= _apply_ruleset_changes(sg, "egress",
                                      existing_egress_rules, request_egress_rules,
                                      module_params["egress"].get("clear_rules", False),
                                      check_mode)
    return changed, sg


def ensure_present(ec2, module_params, check_mode):
    """
    :type module_params: dict
    :type check_mode: bool
    :return: (changed, response_object)
    :rtype: typing.Tuple[bool, dict]
    """

    changed = False
    created, sg = _get_or_create(ec2, module_params, check_mode)
    changed |= created

    # a part of param validation that requires remote state
    if not created and module_params["description"] is not None \
            and module_params["description"] != sg.description:
        raise errors.ValidationError("Changing a security group's description is not supported.")
    if created and check_mode:
        # in this case, sg is a direct dict return as we can't continue changing
        return changed, sg

    updated, sg = _update(sg, module_params, check_mode)
    changed |= updated

    sg.reload()
    return changed, sg.meta.data


def _detach_dependencies(ec2, secgroup_id):
    """Detaches secgroup from instances as a prerequisite for deletion."""
    instances = ec2.instances.filter(Filters=ec2_filters.from_dict({
        "instance.group-id": secgroup_id
    }))
    for inst in instances:
        existing_groups = inst.security_groups
        new_groups = [g for g in existing_groups if g["group-id"] != secgroup_id]
        inst.modify_attribute(Groups=new_groups)


def ensure_absent(ec2, module_params, check_mode):
    """
    :return: changed
    :rtype: bool
    """
    if module_params["id"]:
        sg = _get_existing_secgroup_by_id(ec2, module_params["id"])
    else:
        sg = _get_existing_secgroup_by_name_and_vpc(ec2,
                                                    module_params["name"],
                                                    module_params["vpc"])
    if sg is None:
        return False

    if not check_mode:
        _detach_dependencies(ec2, sg.id)
        sg.delete()
    return True


def main():
    gress_suboptions = dict(
        clear_rules=dict(
            type="bool",
            default=False
        ),
        rules=dict(
            type="list",
            elements="dict",
            options=dict(
                protocol=dict(
                    required=True,
                    choices=["all", "tcp", "udp", "icmp", "icmpv6"]
                ),
                port_from=dict(type="int"),
                port_to=dict(type="int"),
                port=dict(type="int"),
                icmp_type=dict(type="int"),
                icmp_code=dict(type="int"),
                security_groups=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        id=dict(
                            required="true"
                        ),
                        description=dict()
                    )
                ),
                ip_ranges=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        cidr=dict(required="true"),
                        description=dict()
                    )
                )
            ),
            default=[]
        )
    )

    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            vpc=dict(),
            ingress=dict(
                type="dict",
                options=gress_suboptions,
                default=dict()
            ),
            egress=dict(
                type="dict",
                options=gress_suboptions,
                default=dict()
            ),
            **spec.params("auth", "state", "tags", "clear_tags", "name", "description",
                          "id")
        ),
        required_one_of=[
            ("id", "name")
        ]
    )

    ers = do_custom_validation(module.params)
    if ers:
        module.fail_json(msg="Parameter validation failed: \n    {0}".format("\n    ".join(ers)))

    try:
        ec2 = boto.ec2_resource(module.params["auth"])
        if module.params["state"] == "present":
            changed, result = ensure_present(ec2, module.params, module.check_mode)
            result = boto_dict_to_module_return(result)
        else:
            changed = ensure_absent(ec2, module.params, module.check_mode)
            result = None
    except errors.AwsCollectionError as e:
        module.fail_json(msg="{0}: {1}".format(type(e), str(e)))
    # noinspection PyUnboundLocalVariable
    module.exit_json(changed=changed, object=result)


if __name__ == "__main__":
    main()
