def collect_ec2_instances(session):
    """Collect EC2 instance and network information from AWS."""

    ec2 = session.client("ec2")

    instances = []

    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):

                security_groups = [
                    {
                        "group_id": group["GroupId"],
                        "group_name": group["GroupName"],
                    }
                    for group in instance.get("SecurityGroups", [])
                ]

                instance_info = {
                    "instance_id": instance["InstanceId"],
                    "instance_type": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "vpc_id": instance.get("VpcId"),
                    "subnet_id": instance.get("SubnetId"),
                    "private_ip": instance.get("PrivateIpAddress"),
                    "public_ip": instance.get("PublicIpAddress"),
                    "security_groups": security_groups,
                }

                instances.append(instance_info)

    return instances