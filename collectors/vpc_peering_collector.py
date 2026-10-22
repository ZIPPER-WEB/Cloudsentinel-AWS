def collect_vpc_peering_connections(session):
    """Collect AWS VPC peering connection information."""

    ec2 = session.client("ec2")

    peering_connections = []

    paginator = ec2.get_paginator("describe_vpc_peering_connections")

    for page in paginator.paginate():
        for connection in page.get("VpcPeeringConnections", []):

            requester = connection.get("RequesterVpcInfo", {})
            accepter = connection.get("AccepterVpcInfo", {})

            peering_info = {
                "peering_connection_id": connection["VpcPeeringConnectionId"],
                "status": connection.get("Status", {}).get("Code"),
                "requester_vpc_id": requester.get("VpcId"),
                "requester_cidr": requester.get("CidrBlock"),
                "requester_region": requester.get("Region"),
                "accepter_vpc_id": accepter.get("VpcId"),
                "accepter_cidr": accepter.get("CidrBlock"),
                "accepter_region": accepter.get("Region"),
            }

            peering_connections.append(peering_info)

    return peering_connections