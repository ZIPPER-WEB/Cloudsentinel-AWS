def collect_subnets(session):
    """Collect subnet information from AWS."""

    ec2 = session.client("ec2")

    subnets = []

    paginator = ec2.get_paginator("describe_subnets")

    for page in paginator.paginate():
        for subnet in page.get("Subnets", []):

            subnet_info = {
                "subnet_id": subnet["SubnetId"],
                "vpc_id": subnet["VpcId"],
                "cidr_block": subnet["CidrBlock"],
                "availability_zone": subnet["AvailabilityZone"],
                "state": subnet["State"],
                "available_ip_count": subnet["AvailableIpAddressCount"],
            }

            subnets.append(subnet_info)

    return subnets
