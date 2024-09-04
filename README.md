# Invictus-AWS

![alt text](https://github.com/invictus-ir/Microsoft-Extractor-Suite/blob/main/docs/source/Images/Invictus-Incident-Response.jpg?raw=true)

## Getting started with Invictus-AWS
To get started with Invictus-AWS, check out the [Invictus-AWS docs.](https://invictus-aws.readthedocs.io/en/latest/)

## Introduction
Invictus-AWS is a python script that will help automatically enumerate and acquire relevant data from an AWS environment.
The tool doesn't require any installation it can be run as a standalone script with minimal configuration required.
The goal for Invictus-AWS is to allow incident responders or other security personnel to quickly get an insight into an AWS environment to answer the following questions:
- What services are running in an AWS environment.
- For each of the services what are the configuration details.
- What logging is available for each of the services that might be relevant in an incident response scenario. 
- Is there any threat that I can find easily with the CloudTrail logs.

Want to know more about this project?
We did a talk at FIRST Amsterdam 2022 and the slides are available here:
https://github.com/invictus-ir/talks/blob/main/FIRST_2022_TC_AMS_Presentation.pdf


## Get started

To run the script you will have to use the AWS CLI. 

- Install the AWS CLI package, you can simply follow the instructions here (https://aws.amazon.com/cli/) 
- Install Python3 on your local system
- Install the requirements with `$pip3 install -r requirements.txt`
- An account with permissions to access the AWS environment you want to acquire data from
- Configure AWS account with `$aws configure`

Note: This requires the AWS Access Key ID for the account you use to run the script.

The user running the script must have these 2 policies in order to have the necessary permissions :
* The AWS managed - job function policy `ReadOnlyAccess`
* The policy that you can find in `source/files/policy.json`

## How it works

The tool is divided into 4 different steps :
1. The first step performs enumeration of activated AWS services and its details.
2. The second step retrieves configuration details about the activated services.
3. The third step extracts available logs for the activated services.
4. The fourth and last step analyze CloudTrail logs, and only CloudTrail logs, by running Athena queries against it. The queries are written in the file `source/files/queries/yaml`. There are already some queries, but you can remove or add your own. If you add you own queries, be careful to respect this style : `name-of-your-query: ... FROM DATABASE.TABLE ...` , don't specify the database and table.  
The logs used by this step can be CloudTrail logs extracted by step 3 or your own CloudTrail logs. But there are some requirements about what the logs look like. They need to be stored in a S3 bucket in the default format (one JSON file, with a single line containing the event). 

Each step can be run independently. There is no need to have completed step 1 to proceed with step 2.

## Usage

The script runs with a few parameters :  
* `-h` to print out the help menu.
* `-p profile` or `--profile profile`. Specify your aws profile. Default is `default`.
* `-w cloud` or `-w local`. 'cloud' option if you want the results to be stored in a S3 bucket (automatically created). 'local' option if you want the results to be written to local storage. The default option is 'cloud'. So if you want to use 'cloud' option, you can either write nothing, write only `-w` or write `-w cloud`.
* `-r region` or `-A [region]`. Use the first option if you want the tool to analyze only the specified region. Use the second option if you want the tool to analyze all regions. You can also specify a region if you want to start with that one.
* `-s [step,step]`. Provide a comma-separated list of the steps to be executed. 1 = Enumeration. 2 = Configuration. 3 = Logs Extraction. 4 = Logs Analysis. The default option is 1,2,3 as **step 4 has to be executed alone**. So if you want to run the three first steps, you can either write nothing, write only `-s` or write `-s 1,2,3`. If you want to run step 4, then write `-s 4`.
* `-start YYYY-MM-DD`. Start date for the Cloudtrail logs collection. It is recommended to use it every time step 3 is executed as it will be extremely long to collect each logs. It has to be used with `-end` and must only be used with step 3.
* `-end YYYY-MM-DD`. End date for the Cloudtrail logs collection. It is recommended to use it every time step 3 is executed as it will be extremely long to collect each logs. It has to be used with `-start` and must only be used with step 3.
> **_NOTE:_**  The next parameters only apply if you run step 4. You have to collect the logs with step 3 on another execution or by your own means.

* `-b bucket`. Bucket containing the CloudTrail logs. Format is `bucket/subfolders/`.
* `-o bucket`. Bucket where the results of the queries will be stored. Must look like `bucket/[subfolders]/`.
* `-c catalog`. Catalog used by Athena.
* `-d database`. Database used by Athena. You can either input an existing database or a new one that will be created.
* `-t table`. Table used by Athena. You can either input an existing table, input a new one (that will have the same structure as the default one) or input a .ddl file giving details about your new table. An example.ddl is available for you, just add the structure, modify the name of the table and the location of your logs.
* `-f file.yaml`. Your own file containing your queries for the analysis. If you don't want to use or modify the default file, you can use your own by specifying it with this option. The file has to already exist.  
* `-x timeframe`. Used by the queries to filter their results. The query part with the timeframe will automatically be added at the end of your queries if you specify a timeframe. You don't have to add it yourself to your queries.

Default Usage : `python3 invictus-aws.py` will get you into a walkthrough mode  
Power User Usage : `$python3 invictus-aws.py [-h] -w [{cloud,local}] (-r AWS_REGION | -A [ALL_REGIONS]) -s [STEP] [-start YYYY-MM-DD] [-end YYYY-MM-DD] [-b SOURCE_BUCKET] [-o OUTPUT_BUCKET][-c CATALOG] [-d DATABASE] [-t TABLE] [-f QUERY_FILE] [-x TIMEFRAME]`

### Examples

**Acquire data exclusively from the eu-wests-3 region, excluding the Configuration step and store the output locally.** :    
`$python3 invictus-aws.py -r eu-west-3 -s 1,3 -w local`  
*Mind that the CloudTrail logs, if existing, will be written both locally and in a S3 bucket as the analysis step needs the logs to be in a bucket.*

**Acquire data from all region, beginning by eu-west-3, with all the default steps (1,2,3) and with results written in a S3 Bucket.** :   
`$python3 invictus-aws.py -A eu-west-3`

**Analyze CloudTrail logs using the tool default database and table.** :  
`$python3 invictus-aws.py -r eu-west-3 -s 4 -b bucket/path-to-the-existing-logs/ -o bucket/path-to-existing-folder-to-store-the-results/`  
*In this example, the -b option is needed the first time as the default database and table will be created. Then you don't need it anymore as the table is already initialized.  
But don't forget that if you modify your logs source and still want to use the default table, you need to delete it before.*

**Analyze CloudTrail logs using the tool default database and table, filter the results to the last 7 days and write the results locally.** :  
`$python3 invictus-aws.py -r eu-west-3 -w local -s 4 -x 7`  
*In this example, the -b option is not written as explained above. The -o option is also not written as we don't need any output bucket as the results will be written locally.*

**Analyze CloudTrail logs using either a new database or table (with the same structure as the default one)** :  
`$python3 invictus-aws.py -r eu-west-3 -w -s 4 -b bucket/path-to-the-existing-logs/ -o bucket/path-to-existing-folder-to-store-the-results/ -c your-catalog -d your-database -t your-table`  
*In this example, the -b option is needed the first time as the default database and table will be created. Then you don't need it anymore as the table is already initialized.  
But don't forget that if you modify your logs source and still want to use the default table, you need to delete it before.**

**Analyze CloudTrail logs using your existing database and table, using your own query file** :  
`$python3 invictus-aws.py -r eu-west-3 -s 4 -c your-catalog -d your-database -t your-table -f path-to-existing-query-file`  

**Analyze CloudTrail logs using a new table with your own structure.** :  
`$python3 invictus-aws.py -r eu-west-3 -s 4 -b bucket/path-to-the-existing-logs/ -o bucket/path-to-existing-folder-where-to-put-the-results/ -c your-catalog -d your-database -t your-creation-table-file.ddl`  
*You can find an example of ddl file in `source/files`. Just replace the name of the table by the one you want to create, the location by the location of your CloudTrail logs and add the structure of your table. The default table used by the tool is explained here : https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html .*
