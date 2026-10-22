from analyzers.network_analyzer import (
    analyze_security_groups,
    analyze_route_tables,
    analyze_vpc_peering,
)


def test_detects_public_ssh_access():
    security_groups = [{
        "group_id": "sg-test123",
        "inbound_rules": [{
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "ipv4_ranges": ["0.0.0.0/0"],
            "ipv6_ranges": [],
        }],
    }]

    findings = analyze_security_groups(security_groups)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_id"] == "sg-test123"
    assert "SSH" in findings[0]["title"]


def test_ignores_ssh_restricted_to_private_ip():
    security_groups = [{
        "group_id": "sg-private123",
        "inbound_rules": [{
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "ipv4_ranges": ["10.0.0.0/8"],
            "ipv6_ranges": [],
        }],
    }]

    findings = analyze_security_groups(security_groups)

    assert findings == []


def test_detects_public_rdp_access():
    security_groups = [{
        "group_id": "sg-rdp123",
        "inbound_rules": [{
            "protocol": "tcp",
            "from_port": 3389,
            "to_port": 3389,
            "ipv4_ranges": ["0.0.0.0/0"],
            "ipv6_ranges": [],
        }],
    }]

    findings = analyze_security_groups(security_groups)

    assert len(findings) == 1
    assert "RDP" in findings[0]["title"]


def test_all_protocols_creates_only_one_finding():
    security_groups = [{
        "group_id": "sg-all123",
        "inbound_rules": [{
            "protocol": "-1",
            "from_port": None,
            "to_port": None,
            "ipv4_ranges": ["0.0.0.0/0"],
            "ipv6_ranges": [],
        }],
    }]

    findings = analyze_security_groups(security_groups)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "all-protocol" in findings[0]["title"].lower()


def test_invalid_port_range_does_not_crash():
    security_groups = [{
        "group_id": "sg-invalid123",
        "inbound_rules": [{
            "protocol": "tcp",
            "from_port": 3389,
            "to_port": 22,
            "ipv4_ranges": ["0.0.0.0/0"],
            "ipv6_ranges": [],
        }],
    }]

    findings = analyze_security_groups(security_groups)

    assert findings == []


def test_detects_blackhole_route():
    route_tables = [{
        "route_table_id": "rtb-test123",
        "routes": [{
            "destination_cidr": "10.1.0.0/16",
            "destination_ipv6": None,
            "state": "blackhole",
        }],
    }]

    findings = analyze_route_tables(route_tables)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_id"] == "rtb-test123"
    assert findings[0]["title"] == "Blackhole route detected"


def test_ignores_active_vpc_peering():
    peering_connections = [{
        "peering_connection_id": "pcx-active123",
        "status": "active",
    }]

    findings = analyze_vpc_peering(peering_connections)

    assert findings == []


def test_detects_pending_vpc_peering():
    peering_connections = [{
        "peering_connection_id": "pcx-pending123",
        "status": "pending-acceptance",
    }]

    findings = analyze_vpc_peering(peering_connections)

    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert findings[0]["resource_id"] == "pcx-pending123"