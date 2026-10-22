def collect_network_interfaces(session):
    """Collect AWS Elastic Network Interface information."""

    ec2 = session.client("ec2")

    network_interfaces = []

    paginator = ec2.get_paginator("describe_network_interfaces")

    for page in paginator.paginate():
        for eni in page.get("NetworkInterfaces", []):

            security_groups = [
                {
                    "group_id": group["GroupId"],
                    "group_name": group["GroupName"],
                }
                for group in eni.get("Groups", [])
            ]

            private_ips = [
                {
                    "private_ip": address.get("PrivateIpAddress"),
                    "is_primary": address.get("Primary", False),
                    "public_ip": address.get("Association", {}).get("PublicIp"),
                }
                for address in eni.get("PrivateIpAddresses", [])
            ]

            interface_info = {
                "network_interface_id": eni["NetworkInterfaceId"],
                "interface_type": eni.get("InterfaceType"),
                "status": eni.get("Status"),
                "vpc_id": eni.get("VpcId"),
                "subnet_id": eni.get("SubnetId"),
                "availability_zone": eni.get("AvailabilityZone"),
                "description": eni.get("Description"),
                "owner_id": eni.get("OwnerId"),
                "attachment_instance_id": eni.get("Attachment", {}).get("InstanceId"),
                "private_ips": private_ips,
                "security_groups": security_groups,
            }

            network_interfaces.append(interface_info)

    return network_interfaces