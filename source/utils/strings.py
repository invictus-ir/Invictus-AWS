ERROR="[!] invictus-aws.py: error:"

############# main.py #############

TOOL_NAME= """
      _            _      _                                      
     (_)          (_)    | |                                     
      _ _ ____   ___  ___| |_ _   _ ___ ______ __ ___      _____ 
     | | '_ \ \ / / |/ __| __| | | / __|______/ _` \ \ /\ / / __|
     | | | | \ V /| | (__| |_| |_| \__ \     | (_| |\ V  V /\__ \\
     |_|_| |_|\_/ |_|\___|\__|\__,_|___/      \__,_| \_/\_/ |___/
                                                             
                                                             
     Copyright (c) 2024 Invictus Incident Response
     Authors: Antonio Macovei, Rares Bratean & Benjamin Guillouzo
    """


WALKTHROUGHT_ENTRY="[+] Entering Walk–through mode..\n"

STEPS_PRESENTATION="[+] Possible actions :\n   [1] Services Enumeration\n   [2] Services Configuration Acquisition\n   [3] Services Logs Acquisition\n   [4] Logs Analysis"
STEPS_ACTION="[+] Press the number(s) associated with the action(s) you want, separated by a comma if needed: "

STORAGE_PRESENTATION="\n[+] Possible storage :\n   [1] Local\n   [2] Cloud"
STORAGE_ACTION="[+] Press the number associated with the storage you want: "

REGION_PRESENTATION="\n[+] Region possibilities:\n   [1] All regions, with the first region to run on if you want. Mind that this option is not available with the Analysis step.\n   [2] One specific region"
REGION_ACTION="[+] Press the number associated with the operation: "
REGION="\t[+] Region that you want (optional for all regions mode): "

DB_INITIALIZED_PRESENTATION="\n[+] Database Initialization possibilities:\n   [1] The database you want to use is already initialized\n   [2] The database you want to use is not initialized yet"
DB_INITIALIZED_ACTION="[+] Press the number associated with the option you want. If it's the first time you run the tool, press 2: "

INPUT_BUCKET_ACTION="\n[+] Enter the S3 URI of the bucket containing the CloudTrail logs. Format is s3://s3_name/subfolders/ : "
OUTPUT_BUCKET_ACTION="\n[+] Enter the S3 URI of the the where the results of the queries will be stored. Format is s3://s3_name/[subfolders]/ : "

DEFAULT_NAME_PRESENTATION="\n[+] Name possibilities:\n   [1] Creates new database and table, using the default names (cloudtrailanalysis & logs)\n   [2] Creates new database and table, using your own names"
DEFAULT_NAME_ACTION="[+] Press the number associated with the option you want: "

NEW_NAMES_PRESENTATION="\n[+] You will now have to enter the catalog to use and the database and table name you want"
CATALOG_ACTION="\t[+] Catalog name : "
DB_ACTION="\t[+] Database name : "
TABLE_ACTION="\t[+] Table name : "

DEFAULT_STRUCTURE_PRESENTATION="\n[+] Structure file possibilities:\n   [1] Use your own file\n   [2] Use the default structure"
DEFAULT_STRUCTURE_ACTION="[+] Press the number associated with the option you want: "
STRUCTULE_FILE="\t[+] Enter the name of the structure file you want to use for your table : "

DEFAULT_QUERY_PRESENTATION="\n[+] Query file possibilities:\n   [1] Use your own file\n   [2] Use the default query file"
DEFAULT_QUERY_ACTION="[+] Press the number associated with the option you want: "
QUERY_FILE="\t[+] Enter the name of the query file you want to use : "

TIMEFRAME_PRESENTATION="\n[+] Timeframe possibilities:\n   [1] Use a timeframe to filter logs results\n   [2] Don't use a timeframe"
TIMEFRAME_ACTION="[+] Press the number associated with the option you want: "
TIMEFRAME="\t[+] Enter the number of last days to analyze : "

START_END_PRESENTATION="\n[+] You will now have to enter the start and end dates of the logs you want to collect"
START="\t[+] Start date of the logs collection: "
END="\t[+] End date of the logs collection: "