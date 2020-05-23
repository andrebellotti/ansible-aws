# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
# Proprietary software, see LICENSE file.


from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.steampunk.aws.plugins.module_utils import tag_utils, boto, errors
from ansible_collections.steampunk.aws.plugins.module_utils.entity_utils import \
    ModuleEntity, ContainerMergeMode


def get_network_interface_by_id(ec2, eni_id, fail_nonexisting_id=False):
    eni = ec2.NetworkInterface(eni_id)
    try:
        eni.load()
    except boto.ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidNetworkInterfaceId.Malformed",
                                           "InvalidNetworkInterfaceID.NotFound"):
            if fail_nonexisting_id:
                raise errors.ObjectDoesNotExist(
                    "A network interface with id {0} does not exist".format(eni_id)
                )
            return None
        raise
    return eni


class Attachment(ModuleEntity):
    def __init__(self, instance_id, device_index, keep_on_termination, merge_modes=None):
        super(Attachment, self).__init__(merge_modes or {})
        self.instance_id = instance_id
        self.device_index = device_index
        self.keep_on_termination = keep_on_termination

    @classmethod
    def from_boto_dict(cls, boto_dict):
        return cls(
            instance_id=boto_dict["InstanceId"],
            device_index=boto_dict["DeviceIndex"],
            keep_on_termination=not boto_dict["DeleteOnTermination"]
        )

    @classmethod
    def from_module_params(cls, module_params):
        return cls(
            instance_id=module_params["instance"],
            device_index=module_params["device_index"],
            keep_on_termination=module_params["keep_on_termination"]
        )

    def to_module_return(self):
        return dict(instance=self.instance_id, device_index=self.device_index,
                    keep_on_termination=self.keep_on_termination)

    @classmethod
    def properties_modify_prohibited(cls):
        return frozenset()

    @classmethod
    def properties_modify_noop(cls):
        return frozenset()

    def _fill_placeholders(self):
        if self.device_index is None:
            self.device_index = self.PROPERTY_PLACEHOLDER
        if self.keep_on_termination is None:
            self.keep_on_termination = True


class NetworkInterface(ModuleEntity):
    def __init__(self, eni_id, description, subnet_id, security_groups, eni_type, tags, mac_address,
                 attachment, public_ip, private_ip_primary, source_dest_check, state, merge_modes):
        super(NetworkInterface, self).__init__(merge_modes)
        self.eni_id = eni_id
        self.description = description
        self.subnet_id = subnet_id
        self.security_groups = security_groups
        self.eni_type = eni_type
        self.tags = tags
        self.mac_address = mac_address
        self.attachment = attachment
        self.public_ip = public_ip
        self.private_ip_primary = private_ip_primary
        self.source_dest_check = source_dest_check
        self.state = state

    @classmethod
    def interface_type_boto_to_internal(cls, interface_type):
        return {"interface": "normal"}.get(interface_type, interface_type)

    @classmethod
    def interface_type_internal_to_boto(cls, interface_type):
        return {"normal": "interface"}.get(interface_type, interface_type)

    @classmethod
    def from_boto_dict(cls, boto_dict):
        return cls(
            eni_id=boto_dict["NetworkInterfaceId"],
            description=boto_dict["Description"] if boto_dict["Description"] else None,
            subnet_id=boto_dict["SubnetId"],
            security_groups=[sg["GroupId"] for sg in boto_dict["Groups"]],
            eni_type=cls.interface_type_boto_to_internal(boto_dict["InterfaceType"]),
            tags=tag_utils.from_boto3(boto_dict["TagSet"]),
            mac_address=boto_dict["MacAddress"],
            attachment=Attachment.from_boto_dict(boto_dict["Attachment"])
            if "Attachment" in boto_dict and boto_dict["Attachment"] else None,
            public_ip=boto_dict["Association"]["PublicIp"]
            if "Association" in boto_dict and boto_dict["Association"] else None,
            private_ip_primary=boto_dict["PrivateIpAddress"],
            source_dest_check=boto_dict["SourceDestCheck"],
            state="attached"
            if "Attachment" in boto_dict and boto_dict["Attachment"] else "detached",
            merge_modes={}
        )

    @classmethod
    def from_module_params(cls, module_params):
        merge_modes = {}
        merge_modes["tags"] = ContainerMergeMode.OVERRIDE \
            if module_params["clear_tags"] else ContainerMergeMode.MERGE
        merge_modes["security_groups"] = ContainerMergeMode.OVERRIDE \
            if module_params["clear_security_groups"] else ContainerMergeMode.MERGE

        tags = tag_utils.merge_with_name_param(module_params["name"], module_params["tags"])
        attachment = Attachment.from_module_params(module_params["attachment"]) \
            if module_params["attachment"] else None

        return cls(
            eni_id=module_params["id"],
            description=module_params["description"],
            subnet_id=module_params["subnet"],
            security_groups=module_params["security_groups"],
            eni_type=module_params["type"],
            tags=tags,
            attachment=attachment,
            private_ip_primary=module_params["ip"],
            source_dest_check=module_params["source_dest_check"],
            state=module_params["state"],
            # generated remotely
            mac_address=None,
            # controlled by another module
            public_ip=None,
            merge_modes=merge_modes,
        )

    def to_module_return(self):
        return dict(
            id=self.eni_id,
            description=self.description,
            subnet=self.subnet_id,
            security_groups=self.security_groups,
            type=self.eni_type,
            tags=self.tags,
            mac_address=self.mac_address,
            attachment=self.attachment.to_module_return() if self.attachment is not None else None,
            public_ip=self.public_ip,
            ip=self.private_ip_primary,
            source_dest_check=self.source_dest_check,
        )

    @classmethod
    def properties_modify_prohibited(cls):
        return {"subnet_id", "eni_type", "private_ip_primary"}

    @classmethod
    def properties_modify_noop(cls):
        return {"eni_id", "mac_address", "public_ip"}

    def _fill_placeholders(self):
        if self.eni_id is None:
            self.eni_id = self.PROPERTY_PLACEHOLDER
        if self.security_groups is None:
            self.security_groups = [self.PROPERTY_PLACEHOLDER]
        if self.eni_type is None:
            self.eni_type = "normal"
        if self.tags is None:
            self.tags = []
        if self.mac_address is None:
            self.mac_address = self.PROPERTY_PLACEHOLDER
        if self.private_ip_primary is None:
            self.private_ip_primary = self.PROPERTY_PLACEHOLDER
        if self.source_dest_check is None:
            self.source_dest_check = True
