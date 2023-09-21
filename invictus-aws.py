import argparse, sys
from os import path
import datetime

from source.main.IR import IR
from source.utils.utils import *

'''
Define the arguments used when calling the tool
'''
def set_args():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="[+] Show this help message and exit.",
    )

    parser.add_argument(
        "-w",
        "--write",
        nargs="?",
        type=str,
        default="cloud",
        const="cloud",
        choices=['cloud', 'local'],
        help="[+] 'cloud' option if you want the results to be stored in a S3 bucket (automatically created). 'local' option if you want the results to be written to local storage. The default option is 'cloud'. So if you want to use 'cloud' option, you can either write nothing, write only `-w` or write `-w cloud`."
    )

    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument(
        "-r",
        "--aws-region",
        help="[+] Only scan the specified region of the account. Can't be used with -a.",
    )
    group1.add_argument(
        "-A",
        "--all-regions",
        nargs="?",
        type=str,
        const="us-east-1",
        default="not-all",
        help="[+] Scan all the enabled regions of the account. If you specify a region, it will begin by this region. Can't be used with -r.",
    )

    parser.add_argument(
        "-s", 
        "--step", 
        nargs='?', 
        type=str, 
        default="1,2,3",
        const="1,2,3", 
        help="[+] Provide a comma-separated list of the steps to be executed. 1 = Enumeration. 2 = Configuration. 3 = Logs Extraction. 4 = Logs Analysis. The default option is all steps. So if you want to run all the four steps, you can either write nothing, write only `-s` or write `-s 1,2,3,4`."
    )

    parser.add_argument(
        "-start",
        "--start-time",
        help="[+] Start time of the Cloudtrail logs to be collected. Must only be used with step 3. Format is YYYY-MM-DD."
    )

    parser.add_argument(
        "-end",
        "--end-time",
        help="[+] End time of the Cloudtrail logs to be collected. Mudt only be used with step 3. Format is YYYY-MM-DD."
    )

    parser.add_argument(
        "-b",
        "--source-bucket",
        type=str,
        help="[+] Bucket containing the cloudtrail logs. Must look like bucket/subfolders/."
    )

    parser.add_argument(
        "-o",
        "--output-bucket",
        type=str,
        help="[+] Bucket where the results of the queries will be stored. Must look like bucket/subfolders/."
    )

    parser.add_argument(
        "-c",
        "--catalog",
        type=str,
        help="[+] Catalog used by Athena."
    )

    parser.add_argument(
        "-d",
        "--database",
        type=str,
        help="[+] Database used by Athena. You can either input an existing database or a new one that will be created. If so, don't forget to input a .ddl file for your table."
    )

    parser.add_argument(
        "-t",
        "--table",
        type=str,
        help="[+]  Table used by Athena. You can either input an existing table or input a .ddl file giving details about your new table. An example.ddl is available for you, just add the structure, modify the name of the table and the location of your logs."
    )

    return parser.parse_args()

'''
Run the steps of the tool (enum, config, logs extraction) 
dl : True if the user wants to download the results, False if he wants the results to be written in a s3 bucket
region : Region to run the tool in
regionless : "not-all" if the tool is used on only one region. First region to run the tool on otherwise
steps : Steps to run (1 for enum, 2 for config, 3 for logs extraction)
start: Start time for logs collection
end : End time for logs collection
source : Source bucket for the analysis part (4)
output : Output bucket for the analysis part (4)
catalog : Data catalog used with the database 
database : Database containing the table for logs analytics
table : Contains the sql requirements to query the logs
exists ([boolean, boolean]) : If the input db and table already exists
'''
def run_steps(dl, region, regionless, steps, start, end, source, output, catalog, database, table, exists):

    if dl:
        create_folder(ROOT_FOLDER + "/" + region)

    logs = ""

    if "4" in steps: 
        ir = IR(region, dl, steps, source, output, catalog, database, table)
    else :
        ir = IR(region, dl, steps)

    if "4" in steps:
        try:    
            ir.execute_analysis(exists)
        except Exception as e:     
            print(str(e))
    else:
        if "1" in steps:
            try:
                ir.execute_enumeration(regionless)
            except Exception as e: 
                print(str(e))

        if "2" in steps:
            try:
                ir.execute_configuration(regionless)
            except Exception as e: 
                print(str(e))

        if "3" in steps:
            try:
                logs = ir.execute_logs(regionless, start, end)
                if logs == "0":
                    print("[!] Error : Be aware that no Cloudtrail logs were found.")
            except Exception as e: 
                print(str(e))

'''
Search for all enabled regions and verify that the fivent region exists (region that the tool will begin with)
input_region : If we're in this function, the used decided to run the tool on all enabled functions. This given region is the first one that the tool will analyze.
'''
def verify_all_regions(input_region):

    response = try_except(
        ACCOUNT_CLIENT.list_regions,
        RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"],
    )
    regions = response["Regions"]

    region_names = []

    for region in regions:
        region_names.append(region["RegionName"])

    regionless = ""
    if input_region in region_names:
        region_names.remove(input_region)
        region_names.insert(0, input_region)
        regionless = input_region

        return region_names, regionless
    else:
        print(
            "[!] Error : The region you entered doesn't exist or is not enabled. Please enter a valid region. Exiting..."
        )
        sys.exit(-1)

'''
Verify the region inputs and run the steps of the tool for one region
dl : True if the user wants to download the results, False if he wants the results to be written in a s3 bucket
region : Region to run the tool in
'''
def verify_one_region(region):
    good = False

    try:
        response = ACCOUNT_CLIENT.get_region_opt_status(RegionName=region)
        response.pop("ResponseMetadata", None)
        if (
            response["RegionOptStatus"] == "ENABLED_BY_DEFAULT"
            or response["RegionOptStatus"] == "ENABLED"
        ):
            good = True
    except Exception as e:
            print(str(e))
            sys.exit(-1)

    return good

'''
Verify that the steps entered are correct
steps : Steps to verify
source : Source bucket for the analysis part (4)
output : Output bucket for the analysis part (4)
catalog : Catalog used for the analysis part (4)
database : Database used for the analysis part (4)
table : Table used for the analysis part (4)
region : Region to run the tool in
'''
def verify_steps(steps, source, output, catalog, database, table, region):

    #Verifying steps inputs

    for step in steps:
        if step not in POSSIBLE_STEPS:
            print(
            "invictus-aws.py: error: The steps you entered are not allowed. Please enter only valid steps."
            )
            sys.exit(-1)

    if "4" in steps and ("3" in steps or "2" in steps or "1" in steps):
        print(
        "invictus-aws.py: error: Step 4 can only be run alone."
        )
        sys.exit(-1)

    if "4" not in steps and (source != None or output != None or catalog != None or database != None or table != None):
        print(
        "invictus-aws.py: error: You can't use -b, -o, -c, -d, -t with another step than the 4th."
        )
        sys.exit(-1)

    #if db and table already exists (the basic ones if no input was provided)
    db_exists = False
    table_exists = False

    #Verifying Athena inputs

    if "4" in steps:

        athena = boto3.client("athena", region_name=region)

        if catalog is None and database is None and table is None:
            
            #we need to verify if cloudtrailanalysis db and clogs table already exists 

            databases = athena.list_databases(CatalogName="AwsDataCatalog")
            for db in databases["DatabaseList"]:
                if db["Name"] == "cloudtrailanalysis":
                    db_exists = True
                    break
            
            if db_exists:
                tables = athena.list_table_metadata(CatalogName="AwsDataCatalog",DatabaseName="cloudtrailanalysis")
                for tb in tables["TableMetadataList"]:
                    if tb["Name"] == "logs":
                        table_exists = True
                        break

        elif catalog is not None and database is not None and table is not None:

            #Verifying catalog exists
            catalogs = athena.list_data_catalogs()
            if not any(cat['CatalogName'] == catalog for cat in catalogs['DataCatalogsSummary']):
                print("invictus-aws.py: error: the data catalog you entered doesn't exist.")
                sys.exit(-1) 

            databases = athena.list_databases(CatalogName=catalog)
            for db in databases["DatabaseList"]:
                if db["Name"] == database:
                    db_exists = True
                    
            if db_exists:
                tables = athena.list_table_metadata(CatalogName=catalog,DatabaseName=database)
                if table.endswith(".ddl"):
                    exists = path.isfile(table)
                    if not exists:
                        print("invictus-aws.py: error: you have to input a valid .ddl file to create a new table.")
                        sys.exit(-1)
                    else:
                        tmp_table = get_table(table, False)[0]
                else:
                    tmp_table = table
                for tb in tables["TableMetadataList"]:
                    if tb["Name"] == tmp_table:
                        table_exists = True

        else:
            print("invictus-aws.py: error: all or none of these arguments are required: -c/--catalog, -d/--database, -t/--table.")
            sys.exit(-1)
            
        if output == None:
            print("invictus-aws.py: error: the following arguments are required: -o/--output-bucket.")
            sys.exit(-1)

        #if all athena args are none, the source is none but table doesn't exists
        if (catalog == None and database == None and table == None) and source == None and not table_exists: 
            print("invictus-aws.py: error: the following arguments are required: -b/--source-bucket.")
            sys.exit(-1) 
        
        # if all athena args are set, db or table is not set and source is not set : we need to recreate a table so we need the source bucket (no need if .ddl file as the source bucket is hardcoded in)
        if (catalog != None and database != None and table != None) and (not db_exists or not table_exists) and source == None and not table.endswith(".ddl"):
            print("invictus-aws.py: error: the following arguments are required: -b/--source-bucket.")
            sys.exit(-1) 

        if (db_exists and table_exists) and source != None:
            print("invictus-aws.py: error: the following arguments are not asked: -b/--source-bucket.\n[+] Don't forget do delete your table if you want to change the logs source.")
            sys.exit(-1) 
    
    #Verify buckets inputs

    if source != None:
        source = verify_bucket(source, "source")
        if not source.startswith("s3://"):
            source = f"s3://{source}"

    
    if output != None:
        output = verify_bucket(output, "output")
        if not output.startswith("s3://"):
            output = f"s3://{output}"

    exists = [db_exists, table_exists]
            
    return steps, source, output, database, table, exists

'''
Verify that the user inputs regarding the buckets logs are correct
bucket : Bucket we verify it exists
type : Source or output bucket (for log analysis)
'''
def verify_bucket(bucket, type):
    s3 = boto3.resource('s3')

    if not bucket.endswith("/"):
        bucket = bucket+"/"

    name, prefix = get_bucket_and_prefix(bucket)

    source_bucket = s3.Bucket(name)
    if not source_bucket.creation_date:
       print(f"invictus-aws.py: error: the {type} bucket you entered doesn't exists or is not written well. Please verify that the format is 's3-name/[potential-folders]/'")
       sys.exit(-1)

    if prefix:   
        response = S3_CLIENT.list_objects_v2(Bucket=name, Prefix=prefix)
        if 'Contents' not in response or len(response['Contents']) == 0:
            print(f"invictus-aws.py: error: the path of the {type} bucket you entered doesn't exists or is not written well. Please verify that the format is 's3-name/[potential-folders]/'")
            sys.exit(-1)
    
    return bucket

'''
Verify if the date inputs are correct
start : Start time
end : End time
steps : Steps to run
'''
def verify_dates(start, end, steps):

    if "3" not in steps and (start != None or end != None):
        print("invictus-aws.py: error: Only input dates with step 3.")
        sys.exit(-1)

    elif "3" not in steps and (start == None or end == None):
        pass

    else:
        if start != None and end != None:

            present = datetime.datetime.now()

            try:
                start_date = datetime.datetime.strptime(start, "%Y-%m-%d")
            except ValueError:
                print("invictus-aws.py: error: Start date in not in a valid format.")
                sys.exit(-1)

            try:
                end_date = datetime.datetime.strptime(end, "%Y-%m-%d")
            except ValueError:
                print("invictus-aws.py: error: End date in not in a valid format.")
                sys.exit(-1)

            if start_date > present:
                print("invictus-aws.py: error: Start date can not be in the future.")
                sys.exit(-1)
            elif end_date > present:
                print("invictus-aws.py: error: End date can not be in the future.")
                sys.exit(-1)
            elif start_date >= end_date:
                print("invictus-aws.py: error: Start date can not be equal to or more recent than End date.")
                sys.exit(-1)

        elif start == None and end != None:
            print("invictus-aws.py: error: Start date in not defined.")
            sys.exit(-1)
        elif start != None and end == None:
            print("invictus-aws.py: error: End date in not defined.")
            sys.exit(-1)
        elif start == None and end == None:
            print("invictus-aws.py: error: You have to specify start and end time.")
            sys.exit(-1)


'''
Main function of the tool
'''
def main():
    print(
        """
      _            _      _                                      
     (_)          (_)    | |                                     
      _ _ ____   ___  ___| |_ _   _ ___ ______ __ ___      _____ 
     | | '_ \ \ / / |/ __| __| | | / __|______/ _` \ \ /\ / / __|
     | | | | \ V /| | (__| |_| |_| \__ \     | (_| |\ V  V /\__ \\
     |_|_| |_|\_/ |_|\___|\__|\__,_|___/      \__,_| \_/\_/ |___/
                                                             
                                                             
     Copyright (c) 2023 Invictus Incident Response
     Authors: Antonio Macovei, Rares Bratean & Benjamin Guillouzo
    """
    )

    args = set_args()

    dl = True if args.write == 'local' else False
    region = args.aws_region
    all_regions= args.all_regions
    steps = args.step.split(",")

    source = args.source_bucket
    output = args.output_bucket

    start = args.start_time
    end = args.end_time

    catalog = args.catalog
    database = args.database
    table = args.table

    verify_dates(start, end, steps)

    if region:

        if verify_one_region(region):
            steps, source, output, database, table, exists = verify_steps(steps, source, output, catalog, database, table, region)  
            run_steps(dl, region, all_regions, steps, start, end, source, output, catalog, database, table, exists)

    
    else:
        
        region_names, regionless = verify_all_regions(all_regions)

        for name in region_names:
            steps, source, output, database, table, exists = verify_steps(steps, source, output, catalog, database, table, name)  
            run_steps(dl, name, regionless, steps, start, end, source, output, catalog, database, table, exists)


if __name__ == "__main__":
    
    main()
