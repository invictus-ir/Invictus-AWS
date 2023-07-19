import boto3
from botocore.exceptions import ClientError
import json, datetime, string, random, sys, os
from pathlib import Path

'''
TODO
'''
def get_random_chars(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

'''
TODO
'''
def try_except(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except:
        return {"count": 0, "data": [], "identifiers": []}

'''
TODO
'''
def write_s3(bucket, key, content):
    response = S3_CLIENT.put_object(Bucket=bucket, Key=key, Body=content)
    return response

'''
TODO
'''
def print_json(data):
    data = json.dumps(data, indent=4, default=str)
    print(data)

'''
TODO
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
TODO
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
TODO
'''
def fix_json(response):
    if isinstance(response, dict):
        is_dict(response)

    return response

'''
TODO
'''
def create_command(command, output):
    command_output = {}
    command_output["command"] = command
    command_output["output"] = output
    return command_output

'''
TODO
'''
def writefile_s3(bucket, key, filename):
    response = S3_CLIENT.meta.client.upload_file(filename, bucket, key)
    return response

'''
TODO
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
TODO
'''
def write_file(file, mode, content):
    with open(file, mode) as f:
        f.write(content)

'''
TODO
'''
def create_folder(path):
    if not os.path.exists(path):
        os.makedirs(path)
    else:
        print(f"[!] Error : Folder {path} already exists")

'''
TODO
'''
def get_file_folders(bucket_name, prefix=""):
    file_names = []
    folders = []

    default_kwargs = {"Bucket": bucket_name, "Prefix": prefix}
    next_token = ""

    while next_token is not None:
        updated_kwargs = default_kwargs.copy()
        if next_token != "":
            updated_kwargs["ContinuationToken"] = next_token

        response = S3_CLIENT.list_objects_v2(**default_kwargs)
        contents = response.get("Contents")

        for result in contents:
            key = result.get("Key")
            if key[-1] == "/":
                folders.append(key)
            else:
                file_names.append(key)

        next_token = response.get("NextContinuationToken")

    return file_names, folders

'''
TODO
'''
def download_files_from_s3(s3_client, bucket_name, local_path, file_names, folders):
    local_path = Path(local_path)

    for folder in folders:
        folder_path = Path.joinpath(local_path, folder)
        folder_path.mkdir(parents=True, exist_ok=True)

    for file_name in file_names:
        file_path = Path.joinpath(local_path, file_name)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        s3_client.download_file(bucket_name, file_name, str(file_path))

'''
TODO
'''
def run_s3_dl(bucket, path):
    file_names, folders = get_file_folders(S3_CLIENT, bucket)
    download_files_from_s3(
        S3_CLIENT,
        bucket,
        path,
        file_names,
        folders,
    )

"""
src_bucket : bucket where all the logs of the corresponding service are stored
dst_bucket : bucket used in incident response
key_part : part of the logs' path
"""
def copy_s3_bucket(src_bucket, dst_bucket, key_part):
    s3res = boto3.resource("s3")

    response = try_except(S3_CLIENT.list_objects_v2, Bucket=src_bucket)
    contents = response.get("Contents", [])

    for key in contents:
        copy_source = {"Bucket": src_bucket, "Key": key["Key"]}
        new_key = LOGS_KEY + key_part + "/" + src_bucket + "/" + key["Key"]
        try_except(s3res.meta.client.copy, copy_source, dst_bucket, new_key)

'''
TODO
'''
def copy_or_write_s3(key, value, dst_bucket, region):
    if value["action"] == 0:
        write_s3(
            dst_bucket,
            f"{region}/logs/{key}.json",
            json.dumps(value["results"], indent=4, default=str),
        )
    else:
        for src_bucket in value["buckets"]:
            copy_s3_bucket(src_bucket, dst_bucket, value)


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

REGIONLESS_SERVICES = ["S3", "IAM", "SNS", "SQS"]
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
