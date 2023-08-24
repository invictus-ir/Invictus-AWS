import argparse, sys
from difflib import SequenceMatcher 
from click import confirm
from os import path

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
        required=True,
        const="cloud",
        choices=['cloud', 'local'],
        help="[+] Decide where to write the results. 'cloud' will write the results in a s3 bucket. 'local' will write the results locally. Default is 'cloud'."
    )

    group2 = parser.add_mutually_exclusive_group(required=True)
    group2.add_argument(
        "-r",
        "--aws-region",
        help="[+] Only scan the specified region of the account. Can't be used with -a.",
    )
    group2.add_argument(
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
        required=True,
        default="1,2,3,4",
        const="1,2,3,4", 
        help="[+] Comma separated list of the steps to run. 1 = Enumeration. 2 = Configuration. 3 = Logs Extraction. 4 = Log Analysis. Default is 1,2,3,4"
    )

    parser.add_argument(
        "-b",
        "--source-bucket",
        type=str,
        help="[+] Bucket where the logs used for the analysis are stored."
    )

    parser.add_argument(
        "-o",
        "--output-bucket",
        type=str,
        help="[+] Bucket where the results of the analysis are stored."
    )

    parser.add_argument(
        "-c",
        "--catalog",
        type=str,
        help="[+] Data catalog containing the database you want to use."
    )

    parser.add_argument(
        "-d",
        "--database",
        type=str,
        help="[+] Database containing the table you want to use. If the database you input doesn't exist, it'll create it."
    )

    parser.add_argument(
        "-t",
        "--table",
        type=str,
        help="[+] Table for your cloudtrail logs. You can specify an existing table or a .ddl file to create your table."
    )

    return parser.parse_args()

'''
Run the steps of the tool (enum, config, logs extraction) 
dl : True if the user wants to download the results, False if he wants the results to be written in a s3 bucket
region : Region to run the tool in
regionless : "not-all" if the tool is used on only one region. First region to run the tool on otherwise
steps : Steps to run (1 for enum, 2 for config, 3 for logs extraction)
source : Source bucket for the analysis part (4)
output : Output bucket for the analysis part (4)
catalog : Data catalog used with the database 
database : Database containing the table for logs analytics
table : Contains the sql requirements to query the logs
'''
def run_steps(dl, region, regionless, steps, source, output, catalog, database, table):

    if dl:
        create_folder(ROOT_FOLDER + "/" + region)

    logs = ""

    if "4" in steps and "3" not in steps: 
        ir = IR(region, dl, steps, source, output, catalog, database, table)
    else :
        ir = IR(region, dl, steps)

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
            logs = ir.execute_logs(regionless)
        except Exception as e: 
            print(str(e))

    if "4" in steps:
        if "3" in steps and logs == "0":
            print("[!] Error : No cloudtrail logs available")
            sys.exit(-1)
        else:
            try:
                ir.execute_analysis()
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
    response.pop("ResponseMetadata", None)
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

    for step in steps:
        if step not in POSSIBLE_STEPS:
            print(
            "invictus-aws.py: error: The steps you entered are not allowed. Please enter only valid steps."
            )
            sys.exit(-1)

    #Verify Athena#

    new_db = False
    new_db = True

    if "4" in steps and "3" not in steps:

        athena = boto3.client("athena", region_name=region)

        if catalog is None and database is None and table is None:
            pass
        elif catalog is not None and database is not None and table is not None:

            catalogs = athena.list_data_catalogs()
            if not any(cat['CatalogName'] == catalog for cat in catalogs['DataCatalogsSummary']):
                print("invictus-aws.py: error: the data catalog you entered doesn't exist")
                sys.exit(-1) 

            new_db = True
            exist_db = False
            close_db = []
            databases = athena.list_databases(CatalogName=catalog)
            for db in databases["DatabaseList"]:
                diff = SequenceMatcher(None, db["Name"], database).ratio()
                if diff > 0.8 and diff < 1:
                    close_db.append(db["Name"])

                elif diff == 1:
                    new_db = False
                    exist_db = True

            if not exist_db:
                for db in close_db:
                    print(db)
                    if not confirm(f'[!] The database you entered has a really close name to {db}. Do you still want to create {database} ?', default=True):
                        new_db = False
                        database = db
                        break         

            new_table = True
            exist_tb = False
            close_tb = []
            if not new_db:
                tables = athena.list_table_metadata(CatalogName=catalog,DatabaseName=database)
                for tb in tables["TableMetadataList"]:
                    if table.endswith(".ddl"):
                        tmp_table = get_table(table, False)[0]
                    else:
                        tmp_table = table
                    diff = SequenceMatcher(None, tb["Name"], tmp_table).ratio()
                    if diff > 0.8 and diff < 1:
                        close_tb.append(tb["Name"])
                    
                    elif diff == 1:
                        new_table = False
                        exist_tb = True

            if not exist_tb:
                for tb in close_tb:
                    if not confirm(f'[!] The table you entered has a really close name to {tb["Name"]}. Do you still want to create {tmp_table} ?', default=True):
                        new_table = False
                        table = tb["Name"]
                        break

            if new_table :
                exists = path.isfile(table)
                if not exists or not table.endswith(".ddl"):
                    print("invictus-aws.py: error: you have to input a valid .ddl file to create a new table. This error can be raised because you inputted a new database so you need to create your table in, or because the table doesn't exist. ")
                    sys.exit(-1)

        else:
            print("invictus-aws.py: error: all or none of these arguments are required: -c/--catalog, -d/--database, -t/--table")
            sys.exit(-1)


    if "4" in steps:
        if "3" not in steps:
            if (source == None and output == None and catalog == None and database == None and table == None) or output == None:
                print("invictus-aws.py: error: the following arguments are required: -o/--output-bucket")
                sys.exit(-1)

            if catalog is not None and database is not None and table is not None:
                if table.endswith(".ddl") and source != None:
                    print("invictus-aws.py: error: the following arguments are not asked: -b/--source-bucket")
                    sys.exit(-1)
                elif source != None and (new_db == False and new_table == False):
                    print("invictus-aws.py: error: the following arguments are not asked: -b/--source-bucket")
                    sys.exit(-1)

        elif "3" in steps and (source != None or output != None) :
            print("invictus-aws.py: error: the following arguments are not asked: -b/--source-bucket, -o/--output-bucket")
            sys.exit(-1)
    
    #Verify buckets#

    if source != None:
        verify_bucket(source, "source")
        source = f"s3://{source}"

    
    if output != None:
        verify_bucket(output, "output")
        output = f"s3://{output}"

    return steps, source, output, database, table

'''
Verify that the user inputs regarding the buckets logs are correct
bucket : Bucket we verify it exists
type : Source or output bucket (for log analysis)
'''
def verify_bucket(bucket, type):
    s3 = boto3.resource('s3')

    if not bucket.endswith("/"):
        bucket = bucket+"/"

    bucket_content = bucket.split("/", 1)
    name = bucket_content[0]

    source_bucket = s3.Bucket(name)
    if not source_bucket.creation_date:
       print(f"invictus-aws.py: error: the {type} bucket you entered doesn't exists or is not written well. Please verify that the format is 's3-name/[potential-folders]/'")
       sys.exit(-1)

    if len(bucket_content) > 1:   
        path = bucket_content[1]
        response = S3_CLIENT.list_objects_v2(Bucket=name, Prefix=path)
        if 'Contents' not in response or len(response['Contents']) == 0:
            print(f"invictus-aws.py: error: the path of the {type} bucket you entered doesn't exists or is not written well. Please verify that the format is 's3-name/[potential-folders]/'")
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
     Authors: Antonio Macovei & Rares Bratean & Benjamin Guillouzo
    """
    )

    args = set_args()

    dl = True if args.write == 'local' else False
    region = args.aws_region
    all_regions= args.all_regions

    source = args.source_bucket
    output = args.output_bucket

    catalog = args.catalog
    database = args.database
    table = args.table

    if region:

        if verify_one_region(region):
            steps, source, output, database, table = verify_steps(args.step.split(","), source, output, catalog, database, table, region)  
            run_steps(dl, region, all_regions, steps, source, output, catalog, database, table)

    
    else:
        
        region_names, regionless = verify_all_regions(all_regions)

        for name in region_names:
            steps, source, output, database, table = verify_steps(args.step.split(","), source, output, catalog, database, table, name)  
            run_steps(dl, name, regionless, steps, source, output, catalog, database, table)


if __name__ == "__main__":
    main()
