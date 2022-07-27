import boto3, argparse, sys
from tabulate import tabulate

# Creates AWS session.
# Returns session object with specified region and with/without AWS credentials.
def create_session(access_key, secret_key, region):
    try:
        if not access_key or not secret_key:
            return boto3.Session(
                region_name=region
            )
        else:
            return boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region)
    except Exception as e:
        print("Something wrong while creating AWS session. ", e)
        sys.exit()

# Scans all security groups in AWS environment and returns list of IDs.
def describe_all_security_groups(client):
    try:
        all_security_groups = client.describe_security_groups()
    except Exception as e:
        print("Something wrong while gettin data about SG from AWS. ", e)
    security_groups_ids = []
    for group in all_security_groups["SecurityGroups"]:
        security_groups_ids.append(group["GroupId"])
    return security_groups_ids

# Removes from the list security groups which appears in network interfaces.
# Returns unattached GroupID and GroupName as a list of touples.
def describe_unattached_security_groups(all_security_groups, client):
    table_data = []
    try:
        interfaces = client.describe_network_interfaces()
    except Exception as e:
        print("Something wrong while gettin data about NI from AWS. ", e)
    # Scan SGs attached to network interfaces and remove them from AllSecurityGroups if exist.
    for interface in interfaces["NetworkInterfaces"]:
        for group in interface["Groups"]:
            try:
                all_security_groups.remove(group["GroupId"])
            except: # Pass if group not found.
                pass
    # Get details about unattached security groups
    try:
        unattached_security_groups = client.describe_security_groups(GroupIds = all_security_groups)
    except Exception as e:
        print("Something wrong while gettin data about filtered SG from AWS. ", e)

    # Format data to table-format.
    for group in unattached_security_groups["SecurityGroups"]:
        column = group["GroupId"], group["GroupName"]
        table_data.append(column)
        
    return table_data

# Collecting security group rules
# Returns list of groups rules in following format: GroupID, GroupName, Protocol, IP, Port, Description
def describe_unsecure_security_groups(client, ignore_ports=None):
    table_data = []
    ports_to_ignore = []
    if ignore_ports:
        ports_to_ignore = ignore_ports.split(",")
    try:
        all_security_groups = client.describe_security_groups()
    except Exception as e:
        print("Something wrong while getting data about security groups.", e)
    for group in all_security_groups["SecurityGroups"]:
        for ip_permission in group["IpPermissions"]:
            for ip_range in ip_permission["IpRanges"]:
                if ip_range["CidrIp"] != "0.0.0.0/0":
                    continue
                else:
                    try:
                        # Skip rule, only if port to ignore is not a part of range. Otherwise rule will be printed.
                        if (str(ip_permission["FromPort"]) in ports_to_ignore) and (str(ip_permission["ToPort"]) in ports_to_ignore):
                            continue
                        else:
                            port_range = "{0}-{1}".format(str(ip_permission["FromPort"]), str(ip_permission["ToPort"]))
                            column = group["GroupId"], group["GroupName"], ip_permission["IpProtocol"], ip_range["CidrIp"], port_range, group["Description"]
                            table_data.append(column)
                    except Exception as e:
                        pass
    return table_data

# Main function for scanning unattached security groups
def unattached_scanning(session):
    print("Scanning unattached groups.")
    all_security_groups = describe_all_security_groups(session.client("ec2"))
    table_data = describe_unattached_security_groups(all_security_groups, session.client("ec2"))

    print(tabulate(table_data, headers=["Security Group ID", "Security Group Name"], tablefmt='orgtbl'))

# Main function for scanning unsecure security groups
def unsecure_scanning(session, ignore_ports=None):
    print("Security scanning.")
    table_data = describe_unsecure_security_groups(session.client("ec2"), ignore_ports)
    print(tabulate(table_data, headers=["GroupID", "GroupName", "Protocol", "IP", "PortRange", "Description"], tablefmt='orgtbl'))  

def main():
    # Input args
    parser = argparse.ArgumentParser()
    parser.add_argument("region", help="Region to scan e.g eu-west-1.")
    parser.add_argument("mode", help="What to do? unattached - scanning unattached groups | unsecure - scanning for open ports/IPs.")
    parser.add_argument("--accesskey", help="Amazon Access Key ID. If not specified, IAM role will be used instead.")
    parser.add_argument("--secretkey", help="Amazon Secret Access Key. If not specified, IAM role will be used instead.")
    parser.add_argument("--ignoreports", help="Define ports to ignore while scanning separated by ',' e.g 80,443,8080")

    args = parser.parse_args()

    session = create_session(args.accesskey, args.secretkey, args.region)

    if args.mode == "unattached":
        unattached_scanning(session)

    elif args.mode == "unsecure":
        unsecure_scanning(session, args.ignoreports)

    else:
        print("Wrong mode.")
        parser.print_help()

if __name__ == '__main__':
    main()