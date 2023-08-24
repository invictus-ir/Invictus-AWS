import boto3
from botocore.exceptions import ClientError
import json, datetime, string, random, sys, os

'''
Generate random chars
n : number of char to be generated
'''
def get_random_chars(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

'''
try except function
'''
def try_except(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as e:
        return {"count": 0, "error": str(e)}

'''
Print content of json. Used for debug
data : content of the json
'''
def print_json(data):
    data = json.dumps(data, indent=4, default=str)
    print(data)

'''
Verify if the given data are a list
list_data : List to verify
'''
def is_list(list_data):
    for data in list_data:
        if isinstance(data, datetime.datetime):
            data = str(data)
        if isinstance(data, list):
            is_list(data)
        if isinstance(data, dict):
            is_dict(data)

'''
Verify if the given data are a dictionary
data_dict : Dictionary to verify
'''
def is_dict(data_dict):
    for data in data_dict:
        if isinstance(data_dict[data], datetime.datetime):
            data_dict[data] = str(data_dict[data])
        if isinstance(data_dict[data], list):
            is_list(data_dict[data])
        if isinstance(data_dict[data], dict):
            is_dict(data_dict[data])

'''
Used to correct json format
response : Usually the response of a request (boto3, requests)
'''
def fix_json(response):
    if isinstance(response, dict):
        is_dict(response)

    return response

'''
Merge the command and its results
command : command made
output : output of the command
I imagine you guessed it already :)
'''
def create_command(command, output):
    command_output = {}
    command_output["command"] = command
    command_output["output"] = output
    return command_output

'''
Write a local file to a s3 bucket
bucket : Bucket in which the file is uploaded
key : Path where the file is uploaded
filename : file to be uploaded
'''
def writefile_s3(bucket, key, filename):
    response = S3_CLIENT.meta.client.upload_file(filename, bucket, key)
    return response

'''
Create a s3 bucket if needed during the investigation
region : Region where to create the s3
bucket_name : Name of the new bucket
'''
def create_s3_if_not_exists(region, bucket_name):
    """
    Note that for region=us-east-1, AWS necessitates that you leave LocationConstraint blank
    https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html#API_CreateBucket_RequestBody
    """
    s3 = boto3.client("s3", region_name=region)
    response = s3.list_buckets()

    for bkt in response["Buckets"]:
        if bkt["Name"] == bucket_name:
            return bucket_name

    print(f"[+] Logs bucket does not exists, creating it now: {bucket_name}")

    bucket_config = dict()
    if region != "us-east-1":
        bucket_config["CreateBucketConfiguration"] = {"LocationConstraint": region}

    try:
        response = s3.create_bucket(Bucket=bucket_name, **bucket_config)
    except ClientError as e:
        print(e)
        sys.exit(-1)
    return bucket_name

'''
Write content to a new file
file : File to be filled 
mode : Opening mode of the file (w, a, etc)
content : Content to be written in the file
'''
def write_file(file, mode, content):
    with open(file, mode) as f:
        f.write(content)

'''
Create a folder 
path : Path of the folder to be created
'''
def create_folder(path):
        os.makedirs(path, exist_ok=True)

'''
Handle the steps of the content's download of a s3 bucket
bucket : Bucket being copied
path : Local path where to paste the content of the bucket
prefix : Specific folder in the bucket to download
'''
def run_s3_dl(bucket, path, prefix=""):

    paginator = S3_CLIENT.get_paginator('list_objects_v2')
    operation_parameters = {"Bucket": bucket, "Prefix": prefix}

    for page in paginator.paginate(**operation_parameters):
        if 'Contents' in page:
            #print(page)
            for s3_object in page['Contents']:
                s3_key = s3_object['Key']
                local_path = os.path.join(path, s3_key)

                local_directory = os.path.dirname(local_path)
                create_folder(local_directory)

                if not local_path.endswith("/"): 
                    S3_CLIENT.download_file(bucket, s3_key, local_path)

'''
Write content to s3 bucket
bucket : Name of the bucket in which we put data
key : Path in the bucket
content : Data to be put
'''
def write_s3(bucket, key, content):
    response = S3_CLIENT.put_object(Bucket=bucket, Key=key, Body=content)
    return response

"""
Copy the content at a specific path of a s3 bucket to another
src_bucket : bucket where all the logs of the corresponding service are stored
dst_bucket : bucket used in incident response
service : Service of which the logs are copied (s3, ec2, etc)
region : Region where the serice is scanned
prefix : Path of the data to copy to reduce the amount of data
"""
def copy_s3_bucket(src_bucket, dst_bucket, service, region, prefix=""):
    s3res = boto3.resource("s3")

    paginator = S3_CLIENT.get_paginator('list_objects_v2')
    operation_parameters = {"Bucket": src_bucket, "Prefix": prefix}

    for page in paginator.paginate(**operation_parameters):
        if 'Contents' in page:
            for key in page['Contents']:
                copy_source = {"Bucket": src_bucket, "Key": key["Key"]}
                new_key = f"{region}/logs/{service}/{src_bucket}/{key['Key']}"
                try_except(s3res.meta.client.copy, copy_source, dst_bucket, new_key)

'''
Depending on the action content of value (0 or 1), write the data to our s3 bucket, or copy the data to the source bucket to our bucket
key : Name of the service
value : Either logs of the service or the buckets where the logs are stored, based on the const LOGS_RESULTS
dst_bucket : Bucket where to put the data
region : Region where the serice is scanned
'''
def copy_or_write_s3(key, value, dst_bucket, region):
    if value["action"] == 0:
        write_s3(
            dst_bucket,
            f"{region}/logs/{key}.json",
            json.dumps(value["results"], indent=4, default=str),
        )
    else:
        for src_bucket in value["results"]:
            prefix = ""

            if "|" in src_bucket:
                split = src_bucket.split("|")
                bucket = split[0]
                prefix = split[1]
            else:
                bucket = src_bucket

            copy_s3_bucket(bucket, dst_bucket, key, region, prefix)

'''
Depending on the action content of value (0 or 1), write the data to a single json file, or download the content of a s3 bucket
key : Name of the service
value : Either logs of the service or the buckets where the logs are stored, based on the const LOGS_RESULTS
conf : Path to write the results
'''
def write_or_dl(key, value, conf):
    if value["action"] == 0:
        write_file(
            conf + f"/{key}.json",
            "w",
            json.dumps(value["results"], indent=4, default=str),
        )
    else:
        for bucket in value["results"]:
            path = f"{conf}/{key}"
            create_folder(path) 
            prefix = ""
            
            if "|" in bucket:
                split = bucket.split("|")
                bucket = split[0]
                prefix = split[1]
            run_s3_dl(bucket, path, prefix)

'''
Runs an athena query and verifies it worked
region: Region where the query is made
query : Query to be run
bucket : bucket where the results are written

'''
def athena_query(region, query, bucket):

    athena = boto3.client("athena", region_name=region)

    result = athena.start_query_execution(
        QueryString=query,
        ResultConfiguration={"OutputLocation": bucket}
    )
    
    id = result["QueryExecutionId"]
    status = "QUEUED"

    while status != "SUCCEEDED":
        response = athena.get_query_execution(QueryExecutionId=id)
        status = response["QueryExecution"]["Status"]["State"]

        if status == "FAILED" or status == "CANCELLED":
            print(f'[!] Error : {response["QueryExecution"]["Status"]["AthenaError"]["ErrorMessage"]}')
            sys.exit(-1)    
    
    return response

'''
Rename a s3 file (well it copies it, changes the name, then delete the old one)
bucket : Bucket where the file to rename is
folder : Folder where the file to rename is
new_key : New name of the file
old_key : Old name of the file
'''
def rename_file_s3(bucket, folder, new_key, old_key):
    S3_CLIENT.copy_object(
        Bucket=bucket,
        Key=f'{folder}{new_key}',
        CopySource = {"Bucket": bucket, "Key": f"{folder}{old_key}"}
    )

    S3_CLIENT.delete_object(
        Bucket=bucket,
        Key=f"{folder}{old_key}"
    )

'''
Get the table name out of a ddl file
ddl : Ddl file 
get_db : False if you only want the table name. True if you also want the db name that can be present just before the table name.
'''
def get_table(ddl, get_db):
    with open(ddl, "rt") as ddl:
        data = ddl.read()
        table_content = data.split("(", 1)
        table = table_content[0].strip().split(" ")[-1]
        if "." in table and not get_db:
            table = table.split(".")[1]
        return table, data

def get_bucket_and_prefix(bucket):
    if bucket.startswith("s3://"):
        bucket = bucket.replace("s3://", "")
    
    el = bucket.split("/", 1)
    bucket_name = el[0]
    prefix = el[1]

    return bucket_name, prefix


#####################
# RANDOM GENERATION #
#####################

date = datetime.date.today().strftime("%Y-%m-%d")
random_chars = get_random_chars(5)
PREPARATION_BUCKET = "invictus-aws-" + date + "-" + random_chars
LOGS_BUCKET = "invictus-aws-" + date + "-" + random_chars

#########
# FILES #
#########

ROOT_FOLDER = "./results/"
ROLE_JSON = "role.json"

###########
# CLIENTS #
###########

ACCOUNT_CLIENT = boto3.client('account')
S3_CLIENT = boto3.client("s3")
CLOUDWATCH_CLIENT = boto3.client("cloudwatch")
CLOUDTRAIL_CLIENT = boto3.client("cloudtrail")
ROUTE53_CLIENT = boto3.client("route53")
IAM_CLIENT = boto3.client("iam")
GUARDDUTY_CLIENT = None
WAF_CLIENT = None
LAMBDA_CLIENT = None
EC2_CLIENT = None
EB_CLIENT = None
ROUTE53_RESOLVER_CLIENT = None
DYNAMODB_CLIENT = None
RDS_CLIENT = None
EKS_CLIENT = None
ELS_CLIENT = None
SECRETS_CLIENT = None
KINESIS_CLIENT = None
INSPECTOR_CLIENT = None
DETECTIVE_CLIENT = None
MACIE_CLIENT = None
SSM_CLIENT = None
ATHENA_CLIENT = None

'''
Set the clients to the given region.
region : Region where the client will be used
'''
def set_clients(region):
    global LAMBDA_CLIENT
    global WAF_CLIENT
    global EC2_CLIENT
    global EB_CLIENT
    global ROUTE53_RESOLVER_CLIENT
    global DYNAMODB_CLIENT
    global RDS_CLIENT
    global EKS_CLIENT
    global ELS_CLIENT
    global SECRETS_CLIENT
    global KINESIS_CLIENT
    global GUARDDUTY_CLIENT
    global INSPECTOR_CLIENT
    global DETECTIVE_CLIENT
    global MACIE_CLIENT
    global SSM_CLIENT
    global ATHENA_CLIENT

    WAF_CLIENT = boto3.client("wafv2", region_name=region)
    LAMBDA_CLIENT = boto3.client("lambda", region_name=region)
    EC2_CLIENT = boto3.client("ec2", region_name=region)
    EB_CLIENT = boto3.client("elasticbeanstalk", region_name=region)
    ROUTE53_RESOLVER_CLIENT = boto3.client("route53resolver", region_name=region)
    DYNAMODB_CLIENT = boto3.client("dynamodb", region_name=region)
    RDS_CLIENT = boto3.client("rds", region_name=region)
    EKS_CLIENT = boto3.client("eks", region_name=region)
    ELS_CLIENT = boto3.client("es", region_name=region)
    SECRETS_CLIENT = boto3.client("secretsmanager", region_name=region)
    KINESIS_CLIENT = boto3.client("kinesis", region_name=region)
    GUARDDUTY_CLIENT = boto3.client("guardduty", region_name=region)
    INSPECTOR_CLIENT = boto3.client("inspector2", region_name=region)
    DETECTIVE_CLIENT = boto3.client("detective", region_name=region)
    MACIE_CLIENT = boto3.client("macie2", region_name=region)
    SSM_CLIENT = boto3.client("ssm", region_name=region)
    ATHENA_CLIENT = boto3.client("athena", region_name=region)

########
# MISC #
########

POSSIBLE_STEPS = ["1", "2", "3", "4"]

'''
-1 means we didn't enter in the enumerate function associated 
0 means we ran the associated function but the service wasn't available
'''
ENUMERATION_SERVICES = {
    "s3": {"count": -1, "elements": [], "ids": []},
    "wafv2": {"count": -1, "elements": [], "ids": []},
    "lambda": {"count": -1, "elements": [], "ids": []},
    "vpc": {"count": -1, "elements": [], "ids": []},
    "elasticbeanstalk": {"count": -1, "elements": [], "ids": []},
    "route53": {"count": -1, "elements": [], "ids": []},
    "ec2": {"count": -1, "elements": [], "ids": []},
    "iam": {"count": -1, "elements": [], "ids": []},
    "dynamodb": {"count": -1, "elements": [], "ids": []},
    "rds": {"count": -1, "elements": [], "ids": []},
    "eks": {"count": -1, "elements": [], "ids": []},
    "els": {"count": -1, "elements": [], "ids": []},
    "secrets": {"count": -1, "elements": [], "ids": []},
    "kinesis": {"count": -1, "elements": [], "ids": []},
    "cloudwatch": {"count": -1, "elements": [], "ids": []},
    "guardduty": {"count": -1, "elements": [], "ids": []},
    "detective": {"count": -1, "elements": [], "ids": []},
    "inspector": {"count": -1, "elements": [], "ids": []},
    "macie": {"count": -1, "elements": [], "ids": []},
    "cloudtrail-logs": {"count": -1, "elements": [], "ids": []},
    "cloudtrail": {"count": -1, "elements": [], "ids": []},
}

LOGS_RESULTS = {
    "guardduty": {"action": -1,"results": []},
    "cloudtrail-logs": {"action": -1,"results": []},
    "wafv2": {"action": -1,"results": []},
    "vpc": {"action": -1,"results": []},
    "cloudwatch": {"action": -1,"results": []},
    "s3": {"action": -1,"results": []},
    "inspector": {"action": -1,"results": []},
    "macie": {"action": -1,"results": []},
    "rds": {"action": -1,"results": []},
    "route53": {"action": -1,"results": []}
}

