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
    except:
        return {"count": 0, "data": [], "identifiers": []}

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

    print(f"\n[+] Logs bucket does not exists, creating it now: {bucket_name}\n")

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
mode : Oppening mode of the file (w, a, etc)
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
'''
def run_s3_dl(bucket, path, prefix=""):
    s3 = boto3.resource('s3')

    paginator = S3_CLIENT.get_paginator('list_objects_v2')
    operation_parameters = {"Bucket": bucket, "Prefix": prefix}

    for page in paginator.paginate(**operation_parameters):
        if 'Contents' in page:
            for s3_object in page['Contents']:
                s3_key = s3_object['Key']
                local_path = os.path.join(path, s3_key)

                local_directory = os.path.dirname(local_path)
                create_folder(local_directory)

                s3.meta.client.download_file(bucket, s3_key, local_path)

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
value : either logs of the service or the buckets where the logs are stored, based on the const LOGS_RESULTS
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

            copy_s3_bucket(bucket, dst_bucket, key, region, prefix)

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
WAF_CLIENT = boto3.client("wafv2")
LAMBDA_CLIENT = boto3.client("lambda")
EC2_CLIENT = boto3.client("ec2")
EB_CLIENT = boto3.client("elasticbeanstalk")
ROUTE53_CLIENT = boto3.client("route53")
ROUTE53_RESOLVER_CLIENT = boto3.client("route53resolver")
IAM_CLIENT = boto3.client("iam")
DYNAMODB_CLIENT = boto3.client("dynamodb")
RDS_CLIENT = boto3.client("rds")
EKS_CLIENT = boto3.client("eks")
ELS_CLIENT = boto3.client("es")
SECRETS_CLIENT = boto3.client("secretsmanager")
KINESIS_CLIENT = boto3.client("kinesis")
CLOUDWATCH_CLIENT = boto3.client("cloudwatch")
CLOUDTRAIL_CLIENT = boto3.client("cloudtrail")
GUARDDUTY_CLIENT = boto3.client("guardduty")
INSPECTOR_CLIENT = boto3.client("inspector2")
DETECTIVE_CLIENT = boto3.client("detective")
MACIE_CLIENT = boto3.client("macie2")

########
# MISC #
########

POSSIBLE_STEPS = ["1", "2", "3"]

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
