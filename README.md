# Invictus-AWS

## Introduction
Invictus-aws is a python script that will help automatically enumerate and acquire relevant data from an AWS environment.
The tool doesn't require any installation it can be run as a standalone script with minimal configuration required.
The goal for Invictus-AWS is to allow incident responders or other security personnel to quickly get an insight into an AWS environment to answer the following questions:
- What services are running in an AWS environment
- For each of the services what are the configuration details
- What logging is available for each of the services that might be relevant in an incident response scenario. 

Want to know more about this project?
We did a talk at FIRST Amsterdam 2022 and the slides are available here:
https://github.com/invictus-ir/talks/blob/main/FIRST_2022_TC_AMS_Presentation.pdf


## Get started

To run the script you will have to use the AWS CLI. 

- Install the AWS CLI package, you can simply follow the instructions here (https://aws.amazon.com/cli/) 
- Install Python3 on your local system
- Install the requirements with `$pip3 -r requirements.txt`
- An account with permissions to access the AWS environment you want to acquire data from
- Configure AWS account with `$aws configure`

Note: This requires the AWS Access Key ID for the account you use to run the script.

## Usage

The script runs with a few parameters :  
* `-h` to print out help.
* `-w cloud` or `-w local`. 'cloud' option if you want the results to be stored in a s3 bucket (automatically created). 'local' option if you want the results to be written down locally. Default is 'cloud'.
* `-r region` or `-a [region]`. First one if you want the tool to analyze only the region you specify. Second one if you want the tool to analyze all region. You can also specify a region if you want to begin by this one.
* `-s [step,step]`. Comma separated list of the steps to be run out. 1 = Enumeration. 2 = Configuration. 3 = Logs Extraction. 4 = Logs Analysis. Default is 1,2,3,4.
> **_NOTE:_**  The next parameters must only be used if you run step 4 without running step 3 at the same time. Just to remember, step 4 is the logs analysis step. It runs KQL queries on cloudtrail logs.
* `-b`. Bucket containing the cloudtrail logs. Must look like `bucket/subfolders/`.
* `-o`. Bucket where the results of the queries will be stored. Must look like `bucket/subfolders/`.
* `-c`. Catalog used by Athena.
* `-d`. Database used by Athena. You can either input an existing database or a new one that will be created. If so, don't forget to input a .ddl file for your table. 
* `-t`. Table used by Athena. You can either input an existing table or input a .ddl file giving details about your new table. An example.ddl is available for you, just add the structure, modify the name of the table and the location of your logs.

So  usage : `$python3 invictus-aws.py [-h] -w [{cloud,local}] (-r AWS_REGION | -A [ALL_REGIONS]) -s [STEP] [-b SOURCE_BUCKET] [-o OUTPUT_BUCKET][-c CATALOG] [-d DATABASE] [-t TABLE]`


If you want to acquire data from eu-west-3 only, without the Configuration step and with the results written locally :    
`$python3 invictus-aws.py -r eu-west-3 -s 1,3 -w local`

If you want to acquire data from all region, beginning by eu-west-3, with all the steps and with results written in a s3 : 
`$python3 invictus-aws.py -a eu-west-3`
