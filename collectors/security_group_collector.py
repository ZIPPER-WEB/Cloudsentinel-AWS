def collect_security_groups(session):
    """Collect AWS security groups and their inbound/outbound rules."""

    ec2 = session.client("ec2")

    security_groups = []

    paginator = ec2.get_paginator("describe_security_groups")

    for page in paginator.paginate():
        for group in page.get("SecurityGroups", []):

            security_group_info = {
                "group_id": group["GroupId"],
                "group_name": group["GroupName"],
                "description": group.get("Description"),
                "vpc_id": group.get("VpcId"),
                "inbound_rules": [],
                "outbound_rules": [],
            }

            for permission in group.get("IpPermissions", []):
                inbound_rule = {
                    "protocol": permission.get("IpProtocol"),
                    "from_port": permission.get("FromPort"),
                    "to_port": permission.get("ToPort"),
                    "ipv4_ranges": [
                        item.get("CidrIp")
                        for item in permission.get("IpRanges", [])
                    ],
                    "ipv6_ranges": [
                        item.get("CidrIpv6")
                        for item in permission.get("Ipv6Ranges", [])
                    ],
                }

                security_group_info["inbound_rules"].append(inbound_rule)

            for permission in group.get("IpPermissionsEgress", []):
                outbound_rule = {
                    "protocol": permission.get("IpProtocol"),
                    "from_port": permission.get("FromPort"),
                    "to_port": permission.get("ToPort"),
                    "ipv4_ranges": [
                        item.get("CidrIp")
                        for item in permission.get("IpRanges", [])
                    ],
                    "ipv6_ranges": [
                        item.get("CidrIpv6")
                        for item in permission.get("Ipv6Ranges", [])
                    ],
                }

                security_group_info["outbound_rules"].append(outbound_rule)

            security_groups.append(security_group_info)

    return security_groups