"""Main file of the tool, used to run all the steps."""

import argparse, sys
from os import path
import datetime
from re import match

from source.main.ir import IR
from source.utils.utils import *
from source.utils.strings import *

def set_args():
    """Define the arguments used when calling the tool."""
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="[+] Show this help message and exit.",
    )

    parser.add_argument(
        "--menu", 
        action="store_true",
        help="[+] Run in walkthrough mode")
    
    parser.add_argument(
        "-p",
        "--profile",
        nargs="?",
        type=str,
        default="default",
        const="default",
        help="[+] Specify your aws profile. Default profile is 'default'."
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

    group1 = parser.add_mutually_exclusive_group()
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
        help="[+] Table used by Athena. You can either input an existing table or input a .ddl file giving details about your new table. An example.ddl is available for you, just add the structure, modify the name of the table and the location of your logs."
    )

    parser.add_argument(
        "-f",
        "--queryfile",
        nargs='?', 
        default="source/files/queries.yaml",
        const="source/files/queries.yaml", 
        type=str,
        help="[+] Your own file containing your queries for the analysis. If you don't want to use or modify the default file, you can use your own by specifying it with this option. The file has to already exist."
    )

    parser.add_argument(
        "-x",
        "--timeframe",
        type=str,
        help="[+] Used by the queries to filter their results. The timeframe sequence will automatically be added at the end of your queries if you specify a timeframe. You don't have to add it yourself to your queries."
    )

    return parser.parse_args()

def run_steps(dl, region, first_region, steps, start, end, source, output, catalog, database, table, queryfile, exists, timeframe):

    """Run the steps of the tool (enum, config, logs extraction, logs analysis).

    Parameters
    ----------
    dl : bool
        True if the user wants to download the results, False if he wants the results to be written in a s3 bucket
    region : str
        Region in which the tool is executed
    regionless : str
        "not-all" if the tool is used on only one region. First region to run the tool on otherwise
    steps : list of str
        Steps to run (1 for enum, 2 for config, 3 for logs extraction, 4 for analysis)
    start : str
        Start time for logs collection
    end : str  
        End time for logs collection
    source :  str
        Source bucket for the analysis part (4)
    output : str
        Output bucket for the analysis part (4)
    catalog : str
        Data catalog used with the database 
    database : str 
        Database containing the table for logs analytics
    table : str
        Contains the sql requirements to query the logs
    queryfile : str
        File containing the queries
    exists : tuple of bool
        If the input db and table already exists
    timeframe : str
        Time filter for default queries
    """
    if dl:
        create_folder(ROOT_FOLDER + "/" + region)

    logs = ""

    if "4" in steps: 
        ir = IR(region, dl, steps, source, output, catalog, database, table)
    else :
        ir = IR(region, dl, steps)

    if "4" in steps:
        try:    
            ir.execute_analysis(queryfile, exists, timeframe)
        except Exception as e:     
            print(str(e))
    else:
        if "1" in steps:
            try:
                ir.execute_enumeration(first_region)
            except Exception as e: 
                print(str(e))

        if "2" in steps:
            try:
                ir.execute_configuration(first_region)
            except Exception as e: 
                print(str(e))

        if "3" in steps:
            try:
                logs = ir.execute_logs(first_region, start, end)
                if logs == "0":
                    print(f"{ERROR} Be aware that no Cloudtrail logs were found.")
            except Exception as e: 
                print(str(e))

def verify_all_regions(input_region):
    """Search for all enabled regions and verify that the given region exists (region that the tool will begin with).
    
    Parameters
    ----------
    input_region : str
        If we're in this function, the used decided to run the tool on all enabled regions. This given region is the first one that the tool will analyze.
    """
    response = try_except(
        ACCOUNT_CLIENT.list_regions,
        RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"],
    )
    try:
        regions = response["Regions"]
    except KeyError as e:
        print(f"{ERROR} The security token included in the request is expired. Please set a new token before running the tool.")
        sys.exit(-1)

    region_names = []

    for region in regions:
        region_names.append(region["RegionName"])

    if input_region in region_names:
        region_names.remove(input_region)
        region_names.insert(0, input_region)

        return region_names
    elif input_region == "not-all":
        print(f"{ERROR} You have to specify a region option to run the tool : (-r) or (-A).")
        sys.exit(-1)
    else:
        print(f"{ERROR} The region you entered doesn't exist or is not enabled. Please enter a valid region.")
        sys.exit(-1)

def verify_one_region(region):
    """Verify the region inputs and run the steps of the tool for one region.
    
    Parameters
    ----------
    region : str
        Region to run the tool in
        
    Returns
    -------
    enabled : array
        Contains the region if it's enabled
    """
    enabled = []

    try:
        response = ACCOUNT_CLIENT.get_region_opt_status(RegionName=region)
        response.pop("ResponseMetadata", None)
        if (
            response["RegionOptStatus"] == "ENABLED_BY_DEFAULT"
            or response["RegionOptStatus"] == "ENABLED"
        ):
            enabled.append(region)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ExpiredTokenException':
            print(f"{ERROR} The security token included in the request is expired. Please set a new token before running the tool.")
        else:
            print(f"{ERROR} {e}")
        sys.exit(-1)

    return enabled

def verify_steps(steps, source, output, catalog, database, table, region, dl):
    """Verify that the steps entered are correct.

    Parameters
    ----------
    steps : list of str
        Steps to run (1 for enum, 2 for config, 3 for logs extraction, 4 for analysis)
    source :  str
        Source bucket for the analysis part (4)
    output : str
        Output bucket for the analysis part (4)
    catalog : str
        Data catalog used with the database 
    database : str 
        Database containing the table for logs analytics
    table : str
        Contains the sql requirements to query the logs
    region : str
        Region in which the tool is executed
    dl : bool
        True if the user wants to download the results, False if he wants the results to be written in a s3 bucket

    Returns
    -------
    steps : list of str
        Steps to run (1 for enum, 2 for config, 3 for logs extraction, 4 for analysis)
    source :  str
        Source bucket for the analysis part (4)
    output : str
        Output bucket for the analysis part (4)
    database : str 
        Database containing the table for logs analytics
    table : str
        Contains the sql requirements to query the logs
    exists : tuple of bool
        If the input db and table already exists
    """
    #Verifying steps inputs

    verify_steps_input(steps)

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
                print(f"{ERROR} The data catalog you entered doesn't exist.")
                sys.exit(-1) 

            regex_pattern = r'^[a-zA-Z_]{1,255}$'

            if not match(regex_pattern, database):
                print(f"{ERROR} Wrong database name format. Database name can only contains letters and `_`, up to 255 characters.")
                sys.exit(-1) 
            
            if not table.endswith(".ddl") and not match(regex_pattern, table):
                print(f"{ERROR} Wrong table name format. Table name can only contains letters and `_`, up to 255 characters.")
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
                        print(f"{ERROR} you have to input a valid .ddl file to create a new table.")
                        sys.exit(-1)
                    else:
                        tmp_table = get_table(table, False)[0]
                else:
                    tmp_table = table
                for tb in tables["TableMetadataList"]:
                    if tb["Name"] == tmp_table:
                        table_exists = True
                    if tb["Name"] == tmp_table and table.endswith(".ddl"):
                        print(f"[!] Warning : The table {database}.{tmp_table} already exists. Using the existing one..")

        else:
            print(f"{ERROR} All or none of these arguments are required: -c/--catalog, -d/--database, -t/--table.")
            sys.exit(-1)
            
        if output == None and dl == False:
            print(f"{ERROR} The following arguments are required: -o/--output-bucket.")
            sys.exit(-1)
        elif output != None and dl == True: 
            print(f"{ERROR} The following arguments are not asked: -o/--output-bucket.")
            sys.exit(-1)

        if source != None and table.endswith(".ddl"):
            print(f"{ERROR} The following arguments are not asked: -b/--source-bucket.")
            sys.exit(-1)

        #if all athena args are none, the source is none but table doesn't exists
        if (catalog == None and database == None and table == None) and source == None and not table_exists: 
            print(f"{ERROR} The following arguments are required: -b/--source-bucket.")
            sys.exit(-1) 
        
        # if all athena args are set, db or table is not set and source is not set : we need to recreate a table so we need the source bucket (no need if .ddl file as the source bucket is hardcoded in)
        if (catalog != None and database != None and table != None) and (not db_exists or not table_exists) and source == None and not table.endswith(".ddl"):
            print(f"{ERROR} The following arguments are required: -b/--source-bucket.")
            sys.exit(-1) 

        if (db_exists and table_exists) and source != None:
            print(f"{ERROR} The following arguments are not asked: -b/--source-bucket.\n[+] Don't forget to delete your table if you want to change the logs source.")
            sys.exit(-1) 
    
    #Verify buckets inputs

    if source != None:
        source = verify_bucket(source, "source", False)

    
    if output != None:
        output = verify_bucket(output, "output", False)

    exists = [db_exists, table_exists]
            
    return steps, source, output, database, table, exists

def verify_catalog_db(catalog, database, region, to_create):

    #if db already exists (the basic one if no input is provided)
    db_exists = False

    athena = boto3.client("athena", region_name=region)

    if catalog is None and database is None:
        
        #we need to verify if cloudtrailanalysis db already exists 
        databases = athena.list_databases(CatalogName="AwsDataCatalog")
        for db in databases["DatabaseList"]:
            if db["Name"] == "cloudtrailanalysis":
                db_exists = True
                break

    elif catalog is not None and database is not None:
        #Verifying catalog exists
        catalogs = athena.list_data_catalogs()

        if not any(cat['CatalogName'] == catalog for cat in catalogs['DataCatalogsSummary']):
            print(f"{ERROR} The data catalog you entered doesn't exist.")
            sys.exit(-1) 

        regex_pattern = r'^[a-zA-Z_]{1,255}$'

        if not match(regex_pattern, database):
            print(f"{ERROR} Wrong database name format. Database name can only contains letters and `_`, up to 255 characters.")
            sys.exit(-1) 

        databases = athena.list_databases(CatalogName=catalog)
        for db in databases["DatabaseList"]:
            if db["Name"] == database:
                db_exists = True
                break

    else:
        print(f"{ERROR} You have to enter the 3 values : catalog, database and table")
        sys.exit(-1)

    if not db_exists and not to_create:
        print(f"{ERROR} The database you entered doesn't exists.")
        sys.exit(-1)
    
    if db_exists and to_create:
        print(f"{ERROR} The database you entered already exists.")
        sys.exit(-1)

    return db_exists

def verify_table(catalog, database, table, region, to_create, db_exists):

    table_exists = False
    athena = boto3.client("athena", region_name=region)

    if catalog is None and database is None and table is None:
        catalog = "AwsDataCatalog"
        database = "cloudtrailanalysis"
        table = "logs"

    if db_exists:
        tables = athena.list_table_metadata(CatalogName=catalog,DatabaseName=database)
        for tb in tables["TableMetadataList"]:
            if tb["Name"] == "logs":
                table_exists = True

    else:

        regex_pattern = r'^[a-zA-Z_]{1,255}$'
        
        if not match(regex_pattern, table):
            print(f"{ERROR} Wrong table name format. Table name can only contains letters and `_`, up to 255 characters.")
            sys.exit(-1) 

        if db_exists:
            tables = athena.list_table_metadata(CatalogName=catalog,DatabaseName=database)
            for tb in tables["TableMetadataList"]:
                if tb["Name"] == table:
                    table_exists = True
            if not table_exists and not to_create:
                print(f"{ERROR} The table you entered doesn't exists.")
                sys.exit(-1)

    if table_exists and to_create:
        print(f"{ERROR} The table you entered already exists.")
        sys.exit(-1)

    return table_exists

def verify_structure_input(catalog, database, structure, region, db_exists):

    athena = boto3.client("athena", region_name=region)
    table_exists = False

    if structure.endswith(".ddl"):
        exists = path.isfile(structure)
        if not exists:
            print(f"{ERROR} you have to input an existing .ddl file to create a new table.")
            sys.exit(-1)
        else:
            s3 = get_s3_in_ddl(structure)
            verify_bucket(s3, "output", True)
            tmp_table = get_table(structure, False)[0]
    else:
        print(f"{ERROR} you have to input an existing .ddl file to create a new table.")
        sys.exit(-1)

    if db_exists:
        tables = athena.list_table_metadata(CatalogName=catalog,DatabaseName=database)
        for tb in tables["TableMetadataList"]:
            if tb["Name"] == tmp_table:
                table_exists = True

    return table_exists

def verify_queryfile_input(queryfile):

    exists = path.isfile(queryfile)
    if not exists:
        print(f"{ERROR} you have to input an existing query file.")
        sys.exit(-1)

def verify_bucket(bucket, entry_type, is_from_ddl):
    """Verify that the user inputs regarding the buckets logs are correct.

    Parameters
    ----------
    bucket : str
        Bucket we verify it exists
    entry_type : str
        Source or output bucket (for log analysis)

    Returns
    -------
    bucket : str
        Bucket we verify it exists
    """
    

    if not bucket.endswith("/"):
        bucket = bucket+"/"

    if not bucket.startswith("s3://"):
            bucket = f"s3://{bucket}"

    if bucket.startswith("arn:aws:s3:::"):
            print(f"{ERROR} The {entry_type} bucket you entered is not written well. Please verify that the format is 's3://s3-name/[potential-folders]/'")
            sys.exit(-1)
            
    name, prefix = get_bucket_and_prefix(bucket)

    s3 = boto3.resource('s3')
    source_bucket = s3.Bucket(name)

    if not source_bucket.creation_date:
       if is_from_ddl:
           print(f"{ERROR} The {entry_type} bucket you entered as LOCATION in your .DDL file doesn't exists or is not written well. Please verify that the format is 's3://s3-name/[potential-folders]/'")
       else:
        print(f"{ERROR} The {entry_type} bucket you entered doesn't exists or is not written well. Please verify that the format is 's3://s3-name/[potential-folders]/'")
       sys.exit(-1)

    if prefix:   
        response = S3_CLIENT.list_objects_v2(Bucket=name, Prefix=prefix)
        if 'Contents' not in response or len(response['Contents']) == 0:
            if is_from_ddl:
                print(f"{ERROR} The {entry_type} bucket you entered as LOCATION in your .DDL file doesn't exists or is not written well. Please verify that the format is 's3://s3-name/[potential-folders]/'")
            else:
                print(f"{ERROR} The {entry_type} bucket you entered doesn't exists or is not written well. Please verify that the format is 's3://s3-name/[potential-folders]/'")
            sys.exit(-1)
    
    return bucket

def verify_dates(start, end, steps):
    """Verify if the date inputs are correct.
    
    Parameters
    ----------
    start : str
        Start time
    end : str
        End time
    steps : list of str
        Steps to run
    """
    if "3" not in steps and (start != None or end != None):
        print("[!] invictus-aws.py: error:  Only input dates with step 3.")
        sys.exit(-1)

    elif "3" not in steps and (start == None or end == None):
        pass

    else:
        if start != None and end != None:

            present = datetime.datetime.now()

            try:
                start_date = datetime.datetime.strptime(start, "%Y-%m-%d")
            except ValueError:
                print("[!] invictus-aws.py: error:  Start date in not in a valid format.")
                sys.exit(-1)

            try:
                end_date = datetime.datetime.strptime(end, "%Y-%m-%d")
            except ValueError:
                print("[!] invictus-aws.py: error:  End date in not in a valid format.")
                sys.exit(-1)

            if start_date > present:
                print("[!] invictus-aws.py: error:  Start date can not be in the future.")
                sys.exit(-1)
            elif end_date > present:
                print("[!] invictus-aws.py: error:  End date can not be in the future.")
                sys.exit(-1)
            elif start_date >= end_date:
                print("[!] invictus-aws.py: error:  Start date can not be equal to or more recent than End date.")
                sys.exit(-1)

        elif start == None and end != None:
            print("[!] invictus-aws.py: error:  Start date in not defined.")
            sys.exit(-1)
        elif start != None and end == None:
            print("[!] invictus-aws.py: error:  End date in not defined.")
            sys.exit(-1)
        elif start == None and end == None:
            print("[!] invictus-aws.py: error: You have to specify start and end time.")
            sys.exit(-1)

def verify_file(queryfile, steps):
    """Verify if the query file input is correct.
    
    Parameters
    ----------
    queryfile : str
        Yaml file containing the query
    steps : list of str
        Steps to run
    """
    if "4" not in steps and queryfile != "source/files/queries.yaml":
        print("[!] invictus-aws.py: error:  Only input queryfile with step 4.")
        sys.exit(-1)

    if not path.isfile(queryfile):
        print(f"invictus-aws.py: error: {queryfile} does not exist.")
        sys.exit(-1)
    elif not queryfile.endswith(".yaml") and not queryfile.endswith(".yml"):
        print(f"invictus-aws.py: error: Please provide a yaml file as your query file.")
        sys.exit(-1)

def verify_timeframe(timeframe, steps):
    """Verify the input timeframe which is used to filter queries results.

    Parameters
    ----------
    timeframe : str
        Input timeframe
    steps : list of str
        Steps to run
    """
    if timeframe != None:

        if "4" not in steps:
            print("{ERROR} Only input timeframe with step 4.")
            sys.exit(-1)
    
        if not timeframe.isdigit() or int(timeframe) <= 0:
            print("{ERROR} Only input valid number > 0")
            sys.exit(-1)

def verify_steps_input(steps):

    for step in steps:
        if step not in POSSIBLE_STEPS:
            print(f"{ERROR} The steps you entered are not allowed. Please only enter valid steps.")
            sys.exit(-1)

    if "4" in steps and ("3" in steps or "2" in steps or "1" in steps):
        print(f"{ERROR} Step 4 can only be executed alone.")
        sys.exit(-1)

def verify_input(input_name, possible_inputs):
    if input_name not in possible_inputs:
        print("[!] invictus-aws.py: error: The input you entered are not allowed. Please only enter valid inputs.")
        sys.exit(-1)

def verify_region_input(region_choice, region, steps):
    ##all_regions = array of all regions in all mode, array of one region otherwise 

    first_region="not-all"

    try:
        if region_choice == "1":
            try:
                if region:
                    all_regions = verify_all_regions(region)
                    first_region = region
            except IndexError:
                all_regions = verify_all_regions("us-east-1")
                first_region = "us-east-1"
        else:
            all_regions = verify_one_region(region)
    except IndexError:
        print(f"{ERROR} Please only enter valid region and follow the pattern needed.")
        sys.exit(-1)

    return all_regions, first_region

def verify_profile(profile):
    if profile not in boto3.session.Session().available_profiles:
        print("[!] invictus-aws.py: error: The profile you entered does not exist. Please only enter valid profile.")
        sys.exit(-1)


def main():
    """Get the arguments and run the appropriate functions."""
    print(TOOL_NAME)
    
    profile = None
    dl = None
    region = None
    first_region = None
    steps = None
    start = None
    end = None
    source = None
    output = None
    catalog = None
    database = None
    table = None
    queryfile = None
    exists = None
    timeframe = None

    args = set_args()   
    real_arg_count = len(sys.argv) - 1

    if args.menu or real_arg_count == 0 :
        if real_arg_count >= 2:
            print(f"{ERROR} --menu cannot be used with other arguments")
            sys.exit(1)

        ## Walkthough mode
        print(WALKTHROUGHT_ENTRY)

        print(PROFILE_PRESENTATION)
        profile_input = input(PROFILE_ACTION)
        verify_input(profile_input, ["1", "2"])
        if profile_input == "1":
            profile = input(PROFILE)
            verify_profile(profile)
            boto3.setup_default_session(profile_name=profile)       

        print(STEPS_PRESENTATION)
        steps = input(STEPS_ACTION)
        verify_steps_input(steps.split(","))

        print(REGION_PRESENTATION)
        region_choice = input(REGION_ACTION)
        verify_input(region_choice, ["1", "2"])
        if region_choice == "1" and "4" in steps:
            print(f"{ERROR} You cant run the tool on all regions with the Analysis step")
            sys.exit(-1)
        if region_choice == "2":
            region = input(REGION)
        else:
            region = input(ALL_REGION)
        regions, first_region = verify_region_input(region_choice, region, steps)

        print(STORAGE_PRESENTATION)
        storage_input = input(STORAGE_ACTION)
        verify_input(storage_input, ["1", "2"])
        if storage_input == "1":
            dl = True
        else:
            dl = False

        if "3" in steps:
            print(START_END_PRESENTATION)
            start = input(START)
            end = input(END)
            verify_dates(start, end, steps)

        if "4" in steps:
            
            print(DB_INITIALIZED_PRESENTATION)
            init_db_input = input(DB_INITIALIZED_ACTION)
            verify_input(init_db_input, ["1", "2"])

            #[if the database exists, If the table exists]
            exists = [False, False]

            if init_db_input == "2": #aka db is not initialized yet

                print(DEFAULT_NAME_PRESENTATION)
                default_name_input = input(DEFAULT_NAME_ACTION)
                verify_input(default_name_input, ["1", "2"])

                if default_name_input == "2": #aka the guy doesn't want the defaults names 

                    print(NEW_NAMES_PRESENTATION)
                    catalog = input(CATALOG_ACTION)
                    database = input(DB_ACTION)

                    exists[0] = verify_catalog_db(catalog, database, regions[0], True)

                    print(DEFAULT_STRUCTURE_PRESENTATION)
                    default_structure_input = input(DEFAULT_STRUCTURE_ACTION)
                    verify_input(default_structure_input, ["1", "2"])

                    exists = [False, False]
                    if default_structure_input == "1":
                        table = input(STRUCTULE_FILE)
                        exists[1] = verify_structure_input(catalog, database, table, regions[0], exists[0])

                    else:
                        
                        print(TABLE_PRESENTATION)
                        table = input(TABLE_ACTION)
                        exists[1] = verify_table(catalog, database, table, regions[0], True, exists[0])

                        source = input(INPUT_BUCKET_ACTION)
                        verify_bucket(source, "source", False)
                    
                else:
                    catalog = None
                    database = None
                    table = None
                    exists[0] = verify_catalog_db(catalog, database, regions[0], True)
                    exists[1] = verify_table(catalog, database, table, regions[0], True, exists[0])

                    source = input(INPUT_BUCKET_ACTION)
                    verify_bucket(source, "source", False)

                if not dl and ((table and not table.endswith(".ddl")) or not table):
                    output = input(OUTPUT_BUCKET_ACTION)
                    verify_bucket(output, "output", False)               

            else:
                print(NEW_NAMES_PRESENTATION)
                catalog = input(CATALOG_ACTION)
                database = input(DB_ACTION)
                exists[0] = verify_catalog_db(catalog, database, regions[0], False)
                table = input(TABLE_ACTION)
                exists[1] = verify_table(catalog, database, table, regions[0], False, exists[0])

            print(DEFAULT_QUERY_PRESENTATION)
            queryfile = input(DEFAULT_QUERY_ACTION)
            verify_input(queryfile, ["1", "2"])

            if queryfile == "1":
                queryfile = input(QUERY_FILE)
                verify_queryfile_input(queryfile)
            else:
                queryfile = "source/files/queries.yaml"

            print(TIMEFRAME_PRESENTATION)
            timeframe_input = input(TIMEFRAME_ACTION)
            verify_input(timeframe_input, ["1", "2"])

            if timeframe_input == "1":
                timeframe = input(TIMEFRAME)
                verify_timeframe(timeframe, steps)

    else: 

        steps = args.step.split(",")
        verify_steps_input(steps)

        profile = args.profile
        if profile != "default":
            verify_profile(profile)
            boto3.setup_default_session(profile_name=profile)

        region = args.aws_region
        all_regions= args.all_regions

        if region:
            regions, first_region = verify_region_input("2", region, steps)
        else:
            regions, first_region = verify_region_input("1", all_regions, steps)

        dl = True if args.write == 'local' else False

        if "3" in steps:
            start = args.start_time
            end = args.end_time
            verify_dates(start, end, steps)

        source = args.source_bucket
        output = args.output_bucket

        catalog = args.catalog
        database = args.database
        table = args.table

        queryfile = args.queryfile
        verify_file(queryfile, steps)

        timeframe = args.timeframe
        verify_timeframe(timeframe, steps)

        for region in regions:
            steps, source, output, database, table, exists = verify_steps(steps, source, output, catalog, database, table, region, dl)  

    for region in regions:
        run_steps(dl, region, first_region, steps, start, end, source, output, catalog, database, table, queryfile, exists, timeframe)

if __name__ == "__main__":
    main()
        
