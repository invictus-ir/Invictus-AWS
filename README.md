# Invictus-AWS

**Introduction**
Invictus-aws is a python script that will help automatically enumerate and acquire relevant data from an AWS environment.
The tool doesn't require any installation it can be run as a standalone script with minimal configuration required.
The goal for Invictus-AWS is to allow incident responders or other security personnel to quickly get an insight into an AWS environment to answer the following questions:
- What services are running in an AWS environment
- For each of the services what are the configuration details
- What logging is available for each of the services that might be relevant in an incident response scenario. 

Want to know more about this project?
We did a talk at FIRST Amsterdam 2022 and the slides are available here:


**Getting started**

To run the script you will have two options. 
1. Use AWS CloudShell
2. Use the AWS CLI

The setup and prerequisites for both are a bit different. 

**AWS CloudShell**
- An acccount to access to the AWS management console for the environment you want to acquire data from

**AWS CLI**
- Install the AWS CLI package, you can simply follow the instructions here (https://aws.amazon.com/cli/) 
- Install Python3 on your local system
- Install the Python boto3 package
- An account with permissions to access the AWS environment you want to acquire data from

**Setup**
AWS CLI
Configure AWS account:
$aws configure 

Note: This requires the AWS Access Key ID for the account you use to run the script.

**Usage**
AWS CloudShell:
- Launch CloudShell
- Upload the invictus-aws.py file

Within CloudShell or the AWS CLI you can run the following command:

$python3 invictus-aws.py --region=<INSERT REGION>

For example to acquire data from the EU west 1 region you can use:
$python3 invictus-aws.py --region=eu-west-1
