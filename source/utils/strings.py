ERROR="[!] Invictus-AWS: error:"

############# invictus-aws.py #############

TOOL_NAME= """
      _            _      _                                      
     (_)          (_)    | |                                     
      _ _ ____   ___  ___| |_ _   _ ___ ______ __ ___      _____ 
     | | '_ \ \ / / |/ __| __| | | / __|______/ _` \ \ /\ / / __|
     | | | | \ V /| | (__| |_| |_| \__ \     | (_| |\ V  V /\__ \ 
     |_|_| |_|\_/ |_|\___|\__|\__,_|___/      \__,_| \_/\_/ |___/
                                                             
                                                             
     Copyright (c) 2024 Invictus Incident Response
     Authors: Antonio Macovei, Rares Bratean & Benjamin Guillouzo
    """


WALKTHROUGHT_ENTRY="[+] Entering Walk–through mode..\n"

PROFILE_PRESENTATION="[+] Possible profiles: \n   [1] User-defined Profile\n   [2] Default Profile"
PROFILE_ACTION="[+] Select the profile you want to use: "
PROFILE="   [+] Profile you want : "

STEPS_PRESENTATION="\n[+] Possible actions :\n   [1] Services Enumeration\n   [2] Services Configuration Acquisition\n   [3] Log Acquisition\n   [4] Log Analysis"
STEPS_ACTION="[+] Select the action you want to perform, specify multiple actions with a comma (e.g. 1,2,3): "

STORAGE_PRESENTATION="\n[+] Possible storage :\n   [1] Local\n   [2] Cloud"
STORAGE_ACTION="[+] Press the number associated with the storage you want: "

REGION_PRESENTATION="\n[+] Specify your region:\n   [1] All regions, this option is not available with the Analysis step.\n   [2] One specific region"
REGION_ACTION="[+] Press the number associated with the operation: "
REGION="   [+] Region that you want: "
ALL_REGION="   [+] Region that you want (optional): "

DB_INITIALIZED_PRESENTATION="\n[+] Database Initialization possibilities:\n   [1] The database you want to use is already initialized\n   [2] The database you want to use is not initialized yet"
DB_INITIALIZED_ACTION="[+] Press the number associated with the option you want. If it's the first time you run the tool, press 2: "

INPUT_BUCKET_ACTION="\n[+] Enter the S3 URI of the bucket containing the CloudTrail logs. Format is s3://s3_name/subfolders/ : "
OUTPUT_BUCKET_ACTION="\n[+] Enter the S3 URI of where the results of the queries will be stored. Format is s3://s3_name/[subfolders]/ : "

DEFAULT_NAME_PRESENTATION="\n[+] Name possibilities:\n   [1] Creates new database and table, using the default names (cloudtrailanalysis & logs)\n   [2] Creates new database and table, using your own names"
DEFAULT_NAME_ACTION="[+] Press the number associated with the option you want: "

NAMES_PRESENTATION="\n[+] You will now have to enter your existing catalog, database and table"
NEW_NAMES_PRESENTATION="\n[+] You will now have to enter the catalog to use and the database name you want"
TABLE_PRESENTATION="\n[+] Don't forget to enter the name of the table you want"
CATALOG_ACTION="   [+] Catalog name : "
DB_ACTION="   [+] Database name : "
TABLE_ACTION="   [+] Table name : "

DEFAULT_STRUCTURE_PRESENTATION="\n[+] Structure file possibilities:\n   [1] Use your own structure file\n   [2] Use the default structure"
DEFAULT_STRUCTURE_ACTION="[+] Press the number associated with the option you want: "
STRUCTULE_FILE="   [+] Enter the name of the structure file you want to use for your table : "

DEFAULT_QUERY_PRESENTATION="\n[+] Query file possibilities:\n   [1] Use your own file\n   [2] Use the default query file"
DEFAULT_QUERY_ACTION="[+] Press the number associated with the option you want: "
QUERY_FILE="   [+] Enter the name of the query file you want to use : "

TIMEFRAME_PRESENTATION="\n[+] Timeframe possibilities:\n   [1] Use a timeframe to filter logs results\n   [2] Don't use a timeframe"
TIMEFRAME_ACTION="[+] Press the number associated with the option you want: "
TIMEFRAME="   [+] Enter the number of last days to analyze : "

START_END_PRESENTATION="\n[+] Enter the start and end dates of the logs you want to collect"
START="   [+] Start date of the logs collection (YYYY-MM-DD): "
END="   [+] End date of the logs collection (YYYY-MM-DD): "