import boto3
from botocore.exceptions import ClientError
import json, datetime, string, random, sys, os
from pathlib import Path


def get_random_chars(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def try_except(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except:
        return {"count": 0, "data": [], "identifiers": []}

def write_s3(bucket, key, content):
    response = S3_CLIENT.put_object(Bucket=bucket, Key=key, Body=content)
    return response

def writefile_s3(bucket, key, filename):
    response = S3_CLIENT.meta.client.upload_file(filename, bucket, key)
    return response

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

    print("[+] Logs bucket does not exists, creating it now: " + bucket_name)

    bucket_config = dict()
    if region != "us-east-1":
        bucket_config["CreateBucketConfiguration"] = {"LocationConstraint": region}

    try:
        response = s3.create_bucket(Bucket=bucket_name, **bucket_config)
    except ClientError as e:
        print(e)
        sys.exit(-1)
    return bucket_name

def print_json(data):
    data = json.dumps(data, indent=4, default=str)
    print(data)

def is_list(list_data):
    for data in list_data:
        if isinstance(data, datetime.datetime):
            data = str(data)
        if isinstance(data, list):
            is_list(data)
        if isinstance(data, dict):
            is_dict(data)

def is_dict(data_dict):
    for data in data_dict:
        if isinstance(data_dict[data], datetime.datetime):
            data_dict[data] = str(data_dict[data])
        if isinstance(data_dict[data], list):
            is_list(data_dict[data])
        if isinstance(data_dict[data], dict):
            is_dict(data_dict[data])

def fix_json(response):
    if isinstance(response, dict):
        is_dict(response)

    return response

def create_command(command, output):
    command_output = {}
    command_output["command"] = command
    command_output["output"] = output
    return command_output

"""
dl : True if the user specified he wanted the results locally
region : region we're working on
bucket : bucket to write results if the user asked to
step : enumeration, configuration, logs
key : ENUMERATION_KEY, CONFIGURATION_KEY, LOGS_KEY
results : results we want to write or download
mode : w for write or ab for append
"""

def dl_or_write(dl, region, bucket, step, key, results, mode):
    if dl:
        confs = ROOT_FOLDER + region + f"/{step}/"
        create_folder(confs)
        for el in results:
            write_file(
                confs + f"{el}_{step}.json",
                mode,
                json.dumps(results[el], indent=4, default=str),
            )
    else:
        write_s3(
            bucket,
            key,
            json.dumps(results, indent=4, default=str),
        )

def write_file(file, mode, content):
    with open(file, mode) as f:
        f.write(content)

def create_folder(path):
    if not os.path.exists(path):
        os.makedirs(path)
    else:
        print(f"[!] Error : Folder {path} already exists")

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

def download_files_from_s3(s3_client, bucket_name, local_path, file_names, folders):
    local_path = Path(local_path)

    for folder in folders:
        folder_path = Path.joinpath(local_path, folder)
        folder_path.mkdir(parents=True, exist_ok=True)

    for file_name in file_names:
        file_path = Path.joinpath(local_path, file_name)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        s3_client.download_file(bucket_name, file_name, str(file_path))

def run_s3_dl(bucket, path):
    file_names, folders = get_file_folders(S3_CLIENT, bucket)
    download_files_from_s3(
        S3_CLIENT,
        bucket,
        path,
        file_names,
        folders,
    )

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
ENUMERATION_KEY = "enumeration/enumeration.json"
CONFIGURATION_KEY = "configuration/configuration.json"
LOGS_KEY = "logs/"
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
