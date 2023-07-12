import boto3
from botocore.exceptions import ClientError
import json, datetime, string, random


def get_random_chars(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def try_except(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except:
        return {"count": 0, "data": [], "identifiers": []}


def write_s3(bucket, key, content):
    s3 = boto3.resource("s3")
    response = s3.Bucket(bucket).put_object(Key=key, Body=content)
    return response


def writefile_s3(bucket, key, filename):
    s3 = boto3.resource("s3")
    response = s3.meta.client.upload_file(filename, bucket, key)
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

    print("Logs bucket does not exists, creating it now: " + bucket_name)

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


##########
# RANDOM #
##########

date = datetime.date.today().strftime("%Y-%m-%d")
random_chars = get_random_chars(5)
PREPARATION_BUCKET = "invictus-aws-" + date + "-" + random_chars
LOGS_BUCKET = "invictus-aws-" + date + "-" + random_chars

########
# FILES #
########

ROOT_FOLDER = "./results"
ENUMERATION_KEY = "enumeration/enumeration.json"
CONFIGURATION_KEY = "configuration/configuration.json"
LOGS_KEY = "logs/"
ROLE_JSON = "role.json"

###########
# CLIENTS #
###########

ACCOUNT_CLIENT = boto3.client("account")
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
