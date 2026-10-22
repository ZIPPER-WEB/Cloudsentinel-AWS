import boto3

from collectors.vpc_collector import collect_vpcs
from collectors.subnet_collector import collect_subnets
from collectors.route_table_collector import collect_route_tables
from collectors.security_group_collector import collect_security_groups
from collectors.nacl_collector import collect_network_acls
from collectors.ec2_collector import collect_ec2_instances
from collectors.eni_collector import collect_network_interfaces
from collectors.internet_gateway_collector import collect_internet_gateways
from collectors.vpc_peering_collector import collect_vpc_peering_connections

from analyzers.network_analyzer import (
    analyze_security_groups,
    analyze_route_tables,
    analyze_vpc_peering,
)

from analyzers.findings_engine import (
    combine_findings,
    summarize_findings,
)

PROFILE_NAME = "netdoctor"
REGION = "ap-south-1"


def run_scan():
    session = boto3.Session(
        profile_name=PROFILE_NAME,
        region_name=REGION,
    )

    identity = session.client("sts").get_caller_identity()

    vpcs = collect_vpcs(session)
    subnets = collect_subnets(session)
    route_tables = collect_route_tables(session)
    security_groups = collect_security_groups(session)
    network_acls = collect_network_acls(session)
    instances = collect_ec2_instances(session)
    network_interfaces = collect_network_interfaces(session)
    internet_gateways = collect_internet_gateways(session)
    peering_connections = collect_vpc_peering_connections(session)

    security_findings = analyze_security_groups(security_groups)
    route_findings = analyze_route_tables(route_tables)
    peering_findings = analyze_vpc_peering(peering_connections)

    all_findings = combine_findings(
        security_findings,
        route_findings,
        peering_findings,
    )

    summary = summarize_findings(all_findings)

    return {
        "identity": identity.get("Arn", "Unknown"),
        "region": REGION,
        "vpcs": vpcs,
        "subnets": subnets,
        "route_tables": route_tables,
        "security_groups": security_groups,
        "network_acls": network_acls,
        "instances": instances,
        "network_interfaces": network_interfaces,
        "internet_gateways": internet_gateways,
        "peering_connections": peering_connections,
        "findings": all_findings,
        "summary": summary,
    }