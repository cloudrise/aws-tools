import boto3, argparse, sys, time, csv

# Creates AWS session.
# Returns session object with specified region and with/without AWS credentials.
def create_session(accesskey, secretkey, region):
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

# Returns list of WorkSpaces details
def get_workspace_details(session):
    all_workspaces = []
    try:
        client = session.client('workspaces')
        response = client.describe_workspaces()
        while response:  
            all_workspaces += response['Workspaces']
            response = client.describe_workspaces(NextToken = response['NextToken']) if 'NextToken' in response else None # Pagination handling
    except Exception as e:
        print("Something wrong while getting workspaces details. ", e)
    
    return all_workspaces

# Rebuild given workspace
def rebuild_workspace(session, to_rebuild):
    client = session.client('workspaces')
    print("Rebuilding in progress: ", to_rebuild)
    try:
        response = client.rebuild_workspaces(
            RebuildWorkspaceRequests=[
                {
                    'WorkspaceId' : to_rebuild
                }
            ]
        )
    except Exception as e:
        print("Something wrong while rebuilding workspace.", e)

# Start given workspace
def start_workspace(session, to_start):
    client = session.client('workspaces')
    print("Starting in progress: ", to_start)
    try:
        response = client.start_workspaces(
        StartWorkspaceRequests=[
            {
                'WorkspaceId' : to_start
            }
        ]
           )
    except Exception as e:
        print("Something wrong while starting WS. ", e)

# Import users from CSV file
def import_from_csv(path):
    with open(path) as users_csv:
        csv_reader = csv.reader(users_csv)
        user_list = list(csv_reader)
        return user_list

# Build a Workspace list to rebuild
def find_csv_workspaces(session, users, directory_id):
    client = session.client('workspaces')
    to_rebuild = []
    for user in users:
        try:
            response = client.describe_workspaces(
                DirectoryId = directory_id,
                UserName = user[0]
            )
            if not response['Workspaces']:
                print("Workspace for user {} doesn't exist. ".format(user[0]))
            else:
                for workspace in response['Workspaces']:
                    to_rebuild.append(workspace)
        except Exception as e:
            print("Something wrong while describing Workspaces", e)
    return to_rebuild

# Check if all given Workspaces are in available state
def check_workspace_state(session, workspaces = []):
    for workspace in workspaces:
        if workspace['State'] != 'AVAILABLE':
            print('Workspace {} is not ready yet. Username: {}. Next check within 30 seconds.'.format(workspace['WorkspaceId'], workspace['UserName']))
            return False
    return True

def main():

    # Input args
    parser = argparse.ArgumentParser()
    parser.add_argument("region", help="Region where WorkSpaces are e.g eu-west-1.")
    parser.add_argument("mode", help="Rebuild mode: all, csv.")
    parser.add_argument("--directory_id", help="Your directory ID.")
    parser.add_argument("--accesskey", help="Amazon Access Key ID. If not specified, IAM role will be used instead.")
    parser.add_argument("--secretkey", help="Amazon Secret Access Key. If not specified, IAM role will be used instead.")
    args = parser.parse_args()

    session = create_session(args.accesskey, args.secretkey, args.region)

    if args.mode == "all":        
        all_workspaces = get_workspace_details(session)

        print("WorkSpaces must be started before rebuilding.")
        for workspace in all_workspaces:
            if workspace["State"] == "STOPPED":
                start_workspace(session, workspace["WorkspaceId"])
        while not check_workspace_state(session, all_workspaces): # it won't move forward until all workspaces are in available state
            time.sleep(30)
            all_workspaces = get_workspace_details(session) # refresh list details to get new Workspaces state
        confirm = input("Are you sure to REBUILD all WorkSpaces? [YES]: ")
        if confirm == "YES":
            for workspace in all_workspaces:
                rebuild_workspace(session, workspace["WorkspaceId"])
        else:
            print("Rebuilding canceled.")
    elif args.mode == "csv":
        if args.directory_id is not None:
            users_from_csv = import_from_csv("private/input.csv")
            workspaces_from_csv = find_csv_workspaces(session, users_from_csv, args.directory_id)
            for workspace in workspaces_from_csv:
                start_workspace(session, workspace['WorkspaceId'])

            while not check_workspace_state(session, workspaces_from_csv): # it won't move forward until all workspaces are in available state
                time.sleep(30)
                workspaces_from_csv = find_csv_workspaces(session, users_from_csv, args.directory_id) # refresh list details to get new Workspaces state

            confirm = input("Are you sure to REBUILD all WorkSpaces? [YES]: ")
            if confirm == "YES":
                for workspace in workspaces_from_csv:
                    rebuild_workspace(session, workspace['WorkspaceId'])
        elif args.directoryid is None:
            print("Please specify directory ID.")
    else:
        print("Wrong rebuild mode. Available options are: all, csv.")
if __name__ == '__main__':
    main()
