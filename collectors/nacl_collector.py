def collect_network_acls(session):
    """Collect AWS Network ACLs and their rules."""

    ec2 = session.client("ec2")

    network_acls = []

    paginator = ec2.get_paginator("describe_network_acls")

    for page in paginator.paginate():
        for acl in page.get("NetworkAcls", []):

            inbound_rules = []
            outbound_rules = []

            for entry in acl.get("Entries", []):

                rule_info = {
                    "rule_number": entry.get("RuleNumber"),
                    "protocol": entry.get("Protocol"),
                    "action": entry.get("RuleAction"),
                    "egress": entry.get("Egress"),
                    "cidr_block": entry.get("CidrBlock"),
                    "ipv6_cidr_block": entry.get("Ipv6CidrBlock"),
                    "port_range": entry.get("PortRange"),
                }

                if entry.get("Egress"):
                    outbound_rules.append(rule_info)
                else:
                    inbound_rules.append(rule_info)

            acl_info = {
                "network_acl_id": acl["NetworkAclId"],
                "vpc_id": acl["VpcId"],
                "is_default": acl["IsDefault"],
                "inbound_rules": inbound_rules,
                "outbound_rules": outbound_rules,
                "associated_subnets": [
                    association.get("SubnetId")
                    for association in acl.get("Associations", [])
                ],
            }

            network_acls.append(acl_info)

    return network_acls