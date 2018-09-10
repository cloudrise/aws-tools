import boto3, argparse, sys
from tabulate import tabulate

# Creates AWS session.
# Returns session object with specified region and with/without AWS credentials.
def CreateSession(accesskey, secretkey, region):
    try:
        if not accesskey or not secretkey:
            return boto3.Session(
                region_name=region
            )
        else:
            return boto3.Session(
                aws_access_key_id=accesskey,
                aws_secret_access_key=secretkey,
                region_name=region)
    except Exception as e:
        print("Something wrong while creating AWS session. ", e)
        sys.exit()

# Scans all security groups in AWS environment and returns list of IDs.
# Returns all security groups IDs.
def DescribeAllSecurityGroups(client):
    try:
        AllSecurityGroups = client.describe_security_groups()
    except Exception as e:
        print("Something wrong while gettin data about SG from AWS. ", e)
    FilteredSecurityGroups = []
    for group in AllSecurityGroups["SecurityGroups"]:
        FilteredSecurityGroups.append(group["GroupId"])
    return FilteredSecurityGroups

# Removes from the list security groups which appears in network interfaces.
# Returns unattached GroupID and GroupName as a list of touples.
def DescribeUnAttachedSecurityGroups(AllSecurityGroups, client):
    TableData = []
    try:
        interfaces = client.describe_network_interfaces()
    except Exception as e:
        print("Something wrong while gettin data about NI from AWS. ", e)
    # Scan SGs attached to network interfaces and remove them from AllSecurityGroups if exist.
    for interface in interfaces["NetworkInterfaces"]:
        for group in interface["Groups"]:
            try:
                AllSecurityGroups.remove(group["GroupId"])
            except: # Pass if group not found.
                pass
    # Get details about unattached security groups
    try:
        FilteredSecurityGroupsDetails = client.describe_security_groups(GroupIds = AllSecurityGroups)
    except Exception as e:
        print("Something wrong while gettin data about filtered SG from AWS. ", e)

    # Format data to table-format.
    for group in FilteredSecurityGroupsDetails["SecurityGroups"]:
        column = group["GroupId"], group["GroupName"]
        TableData.append(column)
        
    return TableData

# Collecting security group rules
# Returns list of groups rules in following format: GroupID, GroupName, Protocol, IP, Port, Description
def DescribeUnsecureSecurityGroups(client, ignorePorts=None):
    TableData = []
    ignorePortsList = []
    if ignorePorts:
        ignorePortsList = ignorePorts.split(",")
    try:
        AllSecurityGroups = client.describe_security_groups()
    except Exception as e:
        print("Something wrong while getting data about unsecure security groups.", e)
    for group in AllSecurityGroups["SecurityGroups"]:
        for ipPermission in group["IpPermissions"]:
            for ipRange in ipPermission["IpRanges"]:
                if ipRange["CidrIp"] != "0.0.0.0/0":
                    continue
                else:
                    try:
                        # Skip rule, only if port to ignore is not a part of range. Otherwise rule will be printed.
                        if (str(ipPermission["FromPort"]) in ignorePortsList) and (str(ipPermission["ToPort"]) in ignorePortsList):
                            continue
                        else:
                            portRange = "{0}-{1}".format(str(ipPermission["FromPort"]), str(ipPermission["ToPort"]))
                            column = group["GroupId"], group["GroupName"], ipPermission["IpProtocol"], ipRange["CidrIp"], portRange, group["Description"]
                            TableData.append(column)
                    except Exception as e:
                        pass
    return TableData

# Main function for scanning unattached security groups
def UnattachedScanningMain(session):
    print("Scanning unattached groups.")
    AllSecurityGroups = DescribeAllSecurityGroups(session.client("ec2"))
    TableData = DescribeUnAttachedSecurityGroups(AllSecurityGroups, session.client("ec2"))

    print(tabulate(TableData, headers=["Security Group ID", "Security Group Name"], tablefmt='orgtbl'))

# Main function for scanning unsecure security groups
def UnsecureScanningMain(session, ignorePorts=None):
    print("Security scanning.")
    TableData = DescribeUnsecureSecurityGroups(session.client("ec2"), ignorePorts)
    print(tabulate(TableData, headers=["GroupID", "GroupName", "Protocol", "IP", "PortRange", "Description"], tablefmt='orgtbl'))  

def main():
    # Input args
    parser = argparse.ArgumentParser()
    parser.add_argument("region", help="Region to scan e.g eu-west-1.")
    parser.add_argument("mode", help="What to do? unattached - scanning unattached groups | unsecure - scanning for open ports/IPs.")
    parser.add_argument("--accesskey", help="Amazon Access Key ID. If not specified, IAM role will be used instead.")
    parser.add_argument("--secretkey", help="Amazon Secret Access Key. If not specified, IAM role will be used instead.")
    parser.add_argument("--ignoreports", help="Define ports to ignore while scanning separated by ',' e.g 80,443,8080")

    args = parser.parse_args()

    session = CreateSession(args.accesskey, args.secretkey, args.region)

    if args.mode == "unattached":
        UnattachedScanningMain(session)

    elif args.mode == "unsecure":
        UnsecureScanningMain(session, args.ignoreports)

    else:
        print("Wrong mode.")
        parser.print_help()

if __name__ == '__main__':
    main()