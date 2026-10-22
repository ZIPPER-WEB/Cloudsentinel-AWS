import boto3

from botocore.exceptions import BotoCoreError, ClientError
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
from reports.json_report import generate_json_report
from reports.html_report import generate_html_report

PROFILE_NAME = "netdoctor"
REGION = "ap-south-1"


def main():

    print("=" * 55)
    print("                 CLOUDSENTINEL")
    print(" Network Troubleshooting & Security Analyzer")
    print("=" * 55)

    print(f"\nAWS Profile : {PROFILE_NAME}")
    print(f"AWS Region  : {REGION}")

    try:
        session = boto3.Session(
            profile_name=PROFILE_NAME,
            region_name=REGION,
        )

        print("\nConnecting to AWS...")

        sts = session.client("sts")
        identity = sts.get_caller_identity()

        print("AWS authentication successful.")
        print(f"Authenticated identity: {identity['Arn']}")

        print("\nCollecting VPC inventory...")

        vpcs = collect_vpcs(session)

        print(f"\nVPCs discovered: {len(vpcs)}")

        if not vpcs:
            print("No accessible VPCs were found in this region.")

        for vpc in vpcs:

            print("\n" + "-" * 40)
            print(f"VPC ID      : {vpc['vpc_id']}")
            print(f"CIDR Block  : {vpc['cidr_block']}")
            print(f"State       : {vpc['state']}")
            print(f"Default VPC : {vpc['is_default']}")

        print("\nVPC inventory completed successfully.")

        print("\nCollecting subnet inventory...")

        subnets = collect_subnets(session)

        print(f"\nSubnets discovered: {len(subnets)}")

        for subnet in subnets:
                print("-" * 40)
                print(f"Subnet ID       : {subnet['subnet_id']}")
                print(f"VPC ID          : {subnet['vpc_id']}")
                print(f"CIDR Block      : {subnet['cidr_block']}")
                print(f"Availability AZ : {subnet['availability_zone']}")
                print(f"State           : {subnet['state']}")
                print(f"Available IPs   : {subnet['available_ip_count']}")

        print ("\nSubnet inventory completed successfully.")

        print("\nCollecting route table inventory...")

        route_tables = collect_route_tables(session)

        print(f"\nRoute tables discovered: {len(route_tables)}")

        for table in route_tables:
                print("-" * 50)
                print(f"Route Table ID : {table['route_table_id']}")
                print(f"VPC ID         : {table['vpc_id']}")
                print(f"Main Table     : {table['is_main']}")

                print("Associated Subnets:")
                print(table["associated_subnets"] or "No explicit subnet associations")

                print("Routes:")

                for route in table["routes"]:
                    destination = (
                        route["destination_cidr"]
                        or route["destination_ipv6"]
                        or "Unknown destination"
                    )

                    target = (
                        route["target_gateway"]
                        or route["target_instance"]
                        or route["target_network_interface"]
                        or route["target_vpc_peering"]
                        or "Other/Local target"
                    )

                    print(f"  Destination: {destination}")
                    print(f"  Target     : {target}")
                    print(f"  State      : {route['state']}")
                    print()

        print("\nRoute table inventory completed successfully.")

        print("\nAnalyzing route tables...")

        route_findings = analyze_route_tables(route_tables)

        print(f"\nRoute table findings: {len(route_findings)}")

        for finding in route_findings:
                print("-" * 50)
                print(f"Severity      : {finding['severity']}")
                print(f"Resource ID   : {finding['resource_id']}")
                print(f"Finding       : {finding['title']}")
                print(f"Description   : {finding['description']}")
                print(f"Recommendation: {finding['recommendation']}")

        print("\nRoute table analysis completed successfully.")

        print("\nCollecting security group inventory...")

        security_groups = collect_security_groups(session)

        print(f"\nSecurity groups discovered: {len(security_groups)}")

        for group in security_groups:
                print("-" * 50)
                print(f"Group ID   : {group['group_id']}")
                print(f"Group Name : {group['group_name']}")
                print(f"VPC ID     : {group['vpc_id']}")

                print("\nInbound Rules:")

                if not group["inbound_rules"]:
                    print("  No inbound rules")
                
                for rule in group["inbound_rules"]:
                    print(f"  Protocol    : {rule['protocol']}")
                    print(f"  Ports       : {rule['from_port']} - {rule['to_port']}")
                    print(f"  IPv4 Ranges : {rule['ipv4_ranges']}")
                    print(f"  IPv6 Ranges : {rule['ipv6_ranges']}")
                    print()

                print("Outbound Rules:")

                if not group["outbound_rules"]:
                    print("  No outbound rules")

                for rule in group["outbound_rules"]:
                    print(f"  Protocol    : {rule['protocol']}")
                    print(f"  Ports       : {rule['from_port']} - {rule['to_port']}")
                    print(f"  IPv4 Ranges : {rule['ipv4_ranges']}")
                    print(f"  IPv6 Ranges : {rule['ipv6_ranges']}")
                    print()

        print("\nSecurity group inventory completed successfully.")

        print("\nAnalyzing security group configurations...")

        findings = analyze_security_groups(security_groups)

        print(f"\nSecurity findings discovered: {len(findings)}")

        for finding in findings:
                print("-" * 50)
                print(f"Severity      : {finding['severity']}")
                print(f"Resource ID   : {finding['resource_id']}")
                print(f"Finding       : {finding['title']}")
                print(f"Description   : {finding['description']}")
                print(f"Recommendation: {finding['recommendation']}")

        print("\nSecurity analysis completed successfully.")

        print("\nCollecting Network ACL inventory...")

        network_acls = collect_network_acls(session)

        print(f"\nNetwork ACLs discovered: {len(network_acls)}")

        for acl in network_acls:
                print("-" * 50)
                print(f"Network ACL ID : {acl['network_acl_id']}")
                print(f"VPC ID         : {acl['vpc_id']}")
                print(f"Default ACL    : {acl['is_default']}")

                print(f"Associated Subnets: {acl['associated_subnets']}")

                print("\nInbound Rules:")

                for rule in acl["inbound_rules"]:
                    print(
                        f"  Rule: {rule['rule_number']} | "
                        f"Protocol: {rule['protocol']} | "
                        f"Action: {rule['action']} | "
                        f"CIDR: {rule['cidr_block'] or rule['ipv6_cidr_block']} | "
                        f"Ports: {rule['port_range']}"
                    )

                print("\nOutbound Rules:")

                for rule in acl["outbound_rules"]:
                    print(
                        f"  Rule: {rule['rule_number']} | "
                        f"Protocol: {rule['protocol']} | "
                        f"Action: {rule['action']} | "
                        f"CIDR: {rule['cidr_block'] or rule['ipv6_cidr_block']} | "
                        f"Ports: {rule['port_range']}"
                    )

        print("\nNetwork ACL inventory completed successfully.")

        print("\nCollecting EC2 instance inventory...")

        instances = collect_ec2_instances(session)

        print(f"\nEC2 instances discovered: {len(instances)}")

        for instance in instances:
                print("-" * 50)
                print(f"Instance ID : {instance['instance_id']}")
                print(f"Instance Type: {instance['instance_type']}")
                print(f"State       : {instance['state']}")
                print(f"VPC ID      : {instance['vpc_id']}")
                print(f"Subnet ID   : {instance['subnet_id']}")
                print(f"Private IP  : {instance['private_ip']}")
                print(f"Public IP   : {instance['public_ip']}")

                print("Security Groups:")

                for group in instance["security_groups"]:
                    print(
                        f"  {group['group_id']} "
                        f"({group['group_name']})"
                    )

        print("\nEC2 inventory completed successfully.")

        print("\nCollecting network interface inventory...")

        network_interfaces = collect_network_interfaces(session)

        print(
                f"\nNetwork interfaces discovered: "
                f"{len(network_interfaces)}"
            )

        for eni in network_interfaces:
                print("-" * 50)
                print(f"Interface ID : {eni['network_interface_id']}")
                print(f"Interface Type: {eni['interface_type']}")
                print(f"Status       : {eni['status']}")
                print(f"VPC ID       : {eni['vpc_id']}")
                print(f"Subnet ID    : {eni['subnet_id']}")
                print(f"Availability AZ: {eni['availability_zone']}")
                print(f"Description  : {eni['description']}")
                print(f"Attached EC2 : {eni['attachment_instance_id']}")

                print("\nPrivate IP Addresses:")

                for ip in eni["private_ips"]:
                    print(f"  Private IP : {ip['private_ip']}")
                    print(f"  Primary    : {ip['is_primary']}")
                    print(f"  Public IP  : {ip['public_ip']}")

                print("\nSecurity Groups:")

                for group in eni["security_groups"]:
                    print(
                        f"  {group['group_id']} "
                        f"({group['group_name']})"
                    )

        print("\nNetwork interface inventory completed successfully.")

        print("\nCollecting Internet Gateway inventory...")

        internet_gateways = collect_internet_gateways(session)

        print(f"\nInternet Gateways discovered: {len(internet_gateways)}")

        for gateway in internet_gateways:
                print("-" * 50)
                print(f"Internet Gateway ID: {gateway['internet_gateway_id']}")
                print(f"Owner ID           : {gateway['owner_id']}")

                print("Attachments:")

                for attachment in gateway["attachments"]:
                    print(f"  VPC ID: {attachment['vpc_id']}")
                    print(f"  State : {attachment['state']}")

        print("\nInternet Gateway inventory completed successfully.")

        print("\nCollecting VPC Peering inventory...")

        peering_connections = collect_vpc_peering_connections(session)

        print(
                f"\nVPC Peering connections discovered: "
                f"{len(peering_connections)}"
            )

        for connection in peering_connections:
                print("-" * 50)
                print(f"Connection ID : {connection['peering_connection_id']}")
                print(f"Status        : {connection['status']}")
                print(f"Requester VPC : {connection['requester_vpc_id']}")
                print(f"Requester CIDR: {connection['requester_cidr']}")
                print(f"Accepter VPC  : {connection['accepter_vpc_id']}")
                print(f"Accepter CIDR : {connection['accepter_cidr']}")
                print(f"Requester Region: {connection['requester_region']}")
                print(f"Accepter Region : {connection['accepter_region']}")

        print("\nVPC Peering inventory completed successfully.")

        print("\nAnalyzing VPC peering connections...")

        peering_findings = analyze_vpc_peering(
                peering_connections
            )

        print(
                f"\nVPC peering findings: {len(peering_findings)}"
            )

        for finding in peering_findings:
                print("-" * 50)
                print(f"Severity      : {finding['severity']}")
                print(f"Resource ID   : {finding['resource_id']}")
                print(f"Finding       : {finding['title']}")
                print(f"Description   : {finding['description']}")
                print(f"Recommendation: {finding['recommendation']}")

        print("\nVPC peering analysis completed successfully.")

        print("\nCombining all security and network findings...")

        all_findings = combine_findings(
                findings,
                route_findings,
                peering_findings,
            )

        summary = summarize_findings(all_findings)

        print("\n" + "=" * 50)
        print("       CLOUDSENTINEL - SCAN SUMMARY")
        print("=" * 50)

        print(f"Total Findings : {summary['total']}")
        print(f"Critical       : {summary['critical']}")
        print(f"High           : {summary['high']}")
        print(f"Medium         : {summary['medium']}")
        print(f"Low            : {summary['low']}")
        print(f"Informational  : {summary['informational']}")

        print("=" * 50)
        print("\nNetwork analysis completed successfully.")

        print("\nGenerating JSON report...")

        report_path = generate_json_report(
                findings=all_findings,
                summary=summary,
                region=REGION,
            )

        print("\nJSON report saved successfully:")
        print(report_path)

        print("\nGenerating HTML report...")

        html_report_path = generate_html_report(
                findings=all_findings,
                summary=summary,
                region=REGION,
            )

        print("\nHTML report saved successfully:")
        print(html_report_path)

    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        print(f"\nAWS API error: {code}")
        print("Check the AWS profile, permissions, and region.")

    except BotoCoreError as error:
        print(f"\nAWS connection error: {error}")

    except Exception as error:
        print(f"\nUnexpected application error: {error}")


if __name__ == "__main__":
    main()