def collect_route_tables(session):
    """Collect route table and route information from AWS."""

    ec2 = session.client("ec2")

    route_tables = []

    paginator = ec2.get_paginator("describe_route_tables")

    for page in paginator.paginate():
        for table in page.get("RouteTables", []):

            routes = []

            for route in table.get("Routes", []):
                route_info = {
                    "destination_cidr": route.get("DestinationCidrBlock"),
                    "destination_ipv6": route.get("DestinationIpv6CidrBlock"),
                    "target_gateway": route.get("GatewayId"),
                    "target_instance": route.get("InstanceId"),
                    "target_network_interface": route.get("NetworkInterfaceId"),
                    "target_vpc_peering": route.get("VpcPeeringConnectionId"),
                    "state": route.get("State"),
                }

                routes.append(route_info)

            table_info = {
                "route_table_id": table["RouteTableId"],
                "vpc_id": table["VpcId"],
                "routes": routes,
                "associated_subnets": [
                    association.get("SubnetId")
                    for association in table.get("Associations", [])
                    if association.get("SubnetId")
                ],
                "is_main": any(
                    association.get("Main", False)
                    for association in table.get("Associations", [])
                ),
            }

            route_tables.append(table_info)

    return route_tables