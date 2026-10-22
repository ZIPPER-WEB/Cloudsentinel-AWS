import boto3


def collect_vpcs(session):
    """
    Collect VPC information from the selected AWS region.
    This function only reads AWS configuration.
    """

    ec2 = session.client("ec2")

    vpcs = []

    paginator = ec2.get_paginator("describe_vpcs")

    for page in paginator.paginate():

        for vpc in page.get("Vpcs", []):

            vpc_info = {
                "vpc_id": vpc["VpcId"],
                "cidr_block": vpc.get("CidrBlock"),
                "state": vpc.get("State"),
                "is_default": vpc.get("IsDefault"),
                "owner_id": vpc.get("OwnerId"),
            }

            vpcs.append(vpc_info)

    return vpcs