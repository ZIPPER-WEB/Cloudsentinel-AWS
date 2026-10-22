def analyze_security_groups(security_groups):
    """Identify potentially risky inbound security group rules."""

    findings = []

    for group in security_groups:
        group_id = group.get("group_id", "Unknown security group")

        for rule in group.get("inbound_rules", []):
            protocol = rule.get("protocol")
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")

            ipv4_ranges = rule.get("ipv4_ranges", [])
            ipv6_ranges = rule.get("ipv6_ranges", [])

            public_access = (
                "0.0.0.0/0" in ipv4_ranges
                or "::/0" in ipv6_ranges
            )

            if not public_access:
                continue

            # One finding is enough for a rule that allows all protocols.
            if protocol == "-1":
                findings.append({
                    "severity": "HIGH",
                    "resource_id": group_id,
                    "title": "All-protocol inbound access from anywhere",
                    "description": (
                        "A security group permits all protocols "
                        "from a globally scoped IP range."
                    ),
                    "recommendation": (
                        "Review the rule and restrict source ranges "
                        "to the networks that require access."
                    ),
                })
                continue

            # SSH and RDP checks require a TCP port range.
            if protocol != "tcp":
                continue

            if not isinstance(from_port, int) or not isinstance(to_port, int):
                continue

            if from_port > to_port:
                continue

            if from_port <= 22 <= to_port:
                findings.append({
                    "severity": "HIGH",
                    "resource_id": group_id,
                    "title": "Potentially exposed SSH access",
                    "description": (
                        "Inbound TCP access includes port 22 "
                        "from a globally scoped IP range."
                    ),
                    "recommendation": (
                        "Restrict SSH access to trusted IP ranges "
                        "or an approved administrative access path."
                    ),
                })

            if from_port <= 3389 <= to_port:
                findings.append({
                    "severity": "HIGH",
                    "resource_id": group_id,
                    "title": "Potentially exposed RDP access",
                    "description": (
                        "Inbound TCP access includes port 3389 "
                        "from a globally scoped IP range."
                    ),
                    "recommendation": (
                        "Restrict RDP access to trusted IP ranges "
                        "or an approved administrative access path."
                    ),
                })

    return findings

def analyze_route_tables(route_tables):
    """Identify routes that are in a blackhole state."""

    findings = []

    for table in route_tables:
        for route in table.get("routes", []):
            if route.get("state") == "blackhole":
                destination = (
                    route.get("destination_cidr")
                    or route.get("destination_ipv6")
                    or "Unknown destination"
                )

                findings.append({
                    "severity": "HIGH",
                    "resource_id": table.get(
                        "route_table_id", "Unknown route table"
                    ),
                    "title": "Blackhole route detected",
                    "description": (
                        f"Route to {destination} is in a blackhole state."
                    ),
                    "recommendation": (
                        "Inspect the route target and verify that the "
                        "referenced network resource exists and is usable."
                    ),
                })

    return findings


def analyze_vpc_peering(peering_connections):
    """Identify VPC peering connections requiring attention."""

    findings = []

    for connection in peering_connections:
        status = connection.get("status")

        # Active connections do not require a finding.
        if status == "active":
            continue

        # Pending acceptance may be expected; report it separately.
        if status == "pending-acceptance":
            severity = "LOW"
            title = "VPC peering connection awaiting acceptance"
            recommendation = (
                "Confirm that the peering request is expected and "
                "coordinate acceptance with the other VPC owner."
            )

        elif status in ("failed", "rejected", "expired", "deleted"):
            severity = "MEDIUM"
            title = "VPC peering connection is not active"
            recommendation = (
                "Review the peering connection status and determine "
                "whether it should be recreated or removed from planning."
            )

        else:
            severity = "MEDIUM"
            title = "VPC peering connection requires review"
            recommendation = (
                "Inspect the connection status and determine whether "
                "further action is needed."
            )

        findings.append({
            "severity": severity,
            "resource_id": connection.get(
                "peering_connection_id", "Unknown peering connection"
            ),
            "title": title,
            "description": (
                f"The peering connection status is {status!r}, "
                "rather than 'active'."
            ),
            "recommendation": recommendation,
        })

    return findings