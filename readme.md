# SG Scanner
Scanning tool for unused/unattached/unsecure security group on Amazon. If group is not attached to any network interfaces it will be 
returned as unused. Generally all security groups binded to AWS Services (EC2, RDS, Lambda, Load Balancers, WorkSpaces, AppStream and 
more) must be attached to network interface.
Security scan checks all security groups rules for open ports from 0.0.0.0/0.
# Requirments
[Python 2.x or 3.x](https://www.python.org/downloads/)
Python libs: tabulate and boto3

# Installation
```sh
$ pip install boto3
$ pip install tabulate
```
# Usage
SG Scanner uses IAM role by default (if started from EC2 instance). If you want to start it from on-premise host then you should pass credentials. Also region should be given.

Using IAM role:
```sh
$ python sgscanner.py region mode
```
Using credentials:
```sh
$ python sgscanner.py region mode --accesskey="yourAccessKey" --secretkey="yourSecretKey"
```
Usage example:
```sh
$ python sgscanner.py eu-west-1 unattached
$ python sgscanner.py eu-west-1 unsecure --accesskey="ABCDEF" --secretkey="123456"
```
# IAM Policy
Policy with minimum required permissions can be found in `sgscanner-policy.json` file.
