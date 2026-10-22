def collect_internet_gateways(session):
    """Collect AWS Internet Gateway information."""

    ec2 = session.client("ec2")

    internet_gateways = []

    paginator = ec2.get_paginator("describe_internet_gateways")

    for page in paginator.paginate():
        for gateway in page.get("InternetGateways", []):

            attachments = [
                {
                    "vpc_id": attachment.get("VpcId"),
                    "state": attachment.get("State"),
                }
                for attachment in gateway.get("Attachments", [])
            ]

            gateway_info = {
                "internet_gateway_id": gateway["InternetGatewayId"],
                "owner_id": gateway.get("OwnerId"),
                "attachments": attachments,
            }

            internet_gateways.append(gateway_info)

    return internet_gateways