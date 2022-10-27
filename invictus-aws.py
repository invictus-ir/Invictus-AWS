import boto3
from botocore.exceptions import ClientError
import json, datetime, requests, time, os, sys
import string, random, argparse

def get_random_chars(n):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

date = datetime.date.today().strftime("%Y-%m-%d")
random_chars = get_random_chars(5)
PREPARATION_BUCKET = 'invictus-aws-'+ date + '-' + random_chars
LOGS_BUCKET = 'invictus-aws-'+ date + '-' + random_chars

ENUMERATION_KEY = 'enumeration/enumeration.json'
CONFIGURATION_KEY = 'configuration/configuration.json'
LOGS_KEY = 'logs/'

def try_except(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except:
        return {'count': 0, 'data': [], 'identifiers': []}

def write_s3(bucket, key, content):
    s3 = boto3.resource("s3")
    response = s3.Bucket(bucket).put_object(Key=key, Body=content)
    return response

def writefile_s3(bucket, key, filename):
    s3 = boto3.resource('s3')
    response = s3.meta.client.upload_file(filename, bucket, key)
    return response

def create_s3_if_not_exists(region, bucket_name):
    '''
        Note that for region=us-east-1, AWS necessitates that you leave LocationConstraint blank
        https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html#API_CreateBucket_RequestBody
    '''
    s3 = boto3.client('s3',region_name=region)
    response = s3.list_buckets()
    
    for bkt in response['Buckets']:
        if bkt['Name'] == bucket_name:
            return bucket_name

    print("Logs bucket does not exists, creating it now: " + bucket_name)
    
    bucket_config = dict()
    if region != 'us-east-1':
        bucket_config['CreateBucketConfiguration'] = {
            'LocationConstraint': region
        }
    
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

class Enumeration:
    services = {}
    bucket = ''
    region = None
    active_services = []

    def __init__(self, region):
        self.bucket = create_s3_if_not_exists(region, PREPARATION_BUCKET)
        self.active_services = []

    def self_test(self):
        print('Enumeration works')

    def execute(self):
        print('Enumeration')
        self.enumerate_s3()
        self.enumerate_wafv2()
        self.enumerate_lambda()
        self.enumerate_vpc()
        self.enumerate_elasticbeanstalk()

        self.enumerate_route53()
        self.enumerate_ec2()
        self.enumerate_iam()
        self.enumerate_dynamodb()
        self.enumerate_rds()

        self.enumerate_cloudwatch()
        self.enumerate_guardduty()
        self.enumerate_detective()
        self.enumerate_inspector2()
        self.enumerate_maciev2()

        self.enumerate_cloudtrail_logs()
        self.enumerate_cloudtrail_trails()

        write_s3(self.bucket, ENUMERATION_KEY, json.dumps(self.services, indent=4, default=str))
        return self.active_services

    def enumerate_s3(self):
        s3 = boto3.client('s3')
        response = try_except(s3.list_buckets)
        response.pop('ResponseMetadata', None)
        buckets = fix_json(response)

        identifiers = []
        for el in buckets.get('Buckets', []):
            identifiers.append(el['Name'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['s3'] = service
        self.display_progress(service, 's3')
        if service['count'] > 0:
            self.active_services.append('s3')
        return

    def enumerate_wafv2(self):
        wafv2 = boto3.client('wafv2')
        response = try_except(wafv2.list_web_acls, Scope='REGIONAL')
        response.pop('ResponseMetadata', None)
        wafs = response

        identifiers = []
        for el in wafs.get('WebACLs', []):
            identifiers.append(el['ARN'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['wafv2'] = service
        self.display_progress(service, 'wafv2')
        if service['count'] > 0:
            self.active_services.append('wafv2')
        return

    def enumerate_lambda(self):
        lmbd = boto3.client('lambda')
        response = try_except(lmbd.list_functions)
        response.pop('ResponseMetadata', None)
        functions = response

        identifiers = []
        for el in functions.get('Functions', []):
            identifiers.append(el['FunctionName'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['lambda'] = service
        self.display_progress(service, 'lambda')
        if service['count'] > 0:
            self.active_services.append('lambda')
        return

    def enumerate_vpc(self):
        ec2 = boto3.client('ec2')
        response = try_except(ec2.describe_vpcs)
        response.pop('ResponseMetadata', None)
        vpcs = response

        identifiers = []
        for el in vpcs.get('Vpcs', []):
            identifiers.append(el['VpcId'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['vpc'] = service
        self.display_progress(service, 'vpc')
        if service['count'] > 0:
            self.active_services.append('vpc')
        return

    def enumerate_elasticbeanstalk(self):
        eb = boto3.client('elasticbeanstalk')
        response = try_except(eb.describe_environments)
        response.pop('ResponseMetadata', None)
        environments = fix_json(response)

        identifiers = []
        for el in environments.get('Environments', []):
            identifiers.append(el['EnvironmentArn'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['eb'] = service
        self.display_progress(service, 'elasticbeanstalk')
        if service['count'] > 0:
            self.active_services.append('elasticbeanstalk')
        return

    def enumerate_route53(self):
        route53 = boto3.client('route53')
        response = try_except(route53.list_hosted_zones)
        response.pop('ResponseMetadata', None)
        hosted_zones = response

        identifiers = []
        for el in hosted_zones.get('HostedZones', []):
            identifiers.append(el['Id'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['route53'] = service
        self.display_progress(service, 'route53')
        if service['count'] > 0:
            self.active_services.append('route53')
        return

    def enumerate_ec2(self):
        ec2 = boto3.client('ec2')
        response = try_except(ec2.describe_instances)
        response.pop('ResponseMetadata', None)
        instances = fix_json(response)

        identifiers = []
        for res in instances.get('Reservations', []):
            for ins in res['Instances']:
                identifiers.append(ins['InstanceId'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['ec2'] = service
        self.display_progress(service, 'ec2')
        if service['count'] > 0:
            self.active_services.append('ec2')
        return

    def enumerate_iam(self):
        iam = boto3.client('iam')
        response = try_except(iam.list_users)
        response.pop('ResponseMetadata', None)
        users = fix_json(response)

        identifiers = []
        for el in users.get('Users', []):
            identifiers.append(el['Arn'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['iam'] = service
        self.display_progress(service, 'iam')
        if service['count'] > 0:
            self.active_services.append('iam')
        return

    def enumerate_dynamodb(self):
        dynamodb = boto3.client('dynamodb')
        response = try_except(dynamodb.list_tables)
        response.pop('ResponseMetadata', None)
        tables = response

        identifiers = []
        for el in tables.get('TableNames', []):
            identifiers.append(el)

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['dynamodb'] = service
        self.display_progress(service, 'dynamodb')
        if service['count'] > 0:
            self.active_services.append('dynamodb')
        return

    def enumerate_rds(self):
        rds = boto3.client('rds')
        response = try_except(rds.describe_db_instances)
        response.pop('ResponseMetadata', None)
        instances = fix_json(response)

        identifiers = []
        for el in instances.get('DBInstances', []):
            identifiers.append(el['DBInstanceArn'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['rds'] = service
        self.display_progress(service, 'rds')
        if service['count'] > 0:
            self.active_services.append('rds')
        return

    def enumerate_cloudwatch(self):
        cloudwatch = boto3.client('cloudwatch')
        response = try_except(cloudwatch.list_dashboards)
        response.pop('ResponseMetadata', None)
        dashboards = fix_json(response)

        identifiers = []
        for el in dashboards.get('DashboardEntries', []):
            identifiers.append(el['DashboardArn'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['cloudwatch'] = service
        self.display_progress(service, 'cloudwatch')
        if service['count'] > 0:
            self.active_services.append('cloudwatch')
        return

    def enumerate_cloudtrail_logs(self):
        cloudtrail = boto3.client('cloudtrail')
        response = try_except(cloudtrail.lookup_events, MaxResults=1)
        response.pop('ResponseMetadata', None)
        events = fix_json(response)

        identifiers = []
        for el in events.get('Events', []):
            identifiers.append(el['EventId'])

        service = {'count': len(identifiers), 'identifiers': []}
        self.services['cloudtrail-logs'] = service
        self.display_progress(service, 'cloudtrail-logs', no_list=True)
        if service['count'] > 0:
            self.active_services.append('cloudtrail-logs')
        return
    
    def enumerate_cloudtrail_trails(self):
        cloudtrail = boto3.client('cloudtrail')
        response = try_except(cloudtrail.list_trails)
        response.pop('ResponseMetadata', None)
        trails = fix_json(response)

        identifiers = []
        for trail in trails.get('Trails', []):
            identifiers.append(trail['Name'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['cloudtrail-trails'] = service
        self.display_progress(service, 'cloudtrail-trails')
        if service['count'] > 0:
            self.active_services.append('cloudtrail-trails')
        return

    def enumerate_guardduty(self):
        guardduty = boto3.client('guardduty')
        response = try_except(guardduty.list_detectors)
        response.pop('ResponseMetadata', None)
        detectors = response

        identifiers = []
        for el in detectors.get('DetectorIds', []):
            identifiers.append(el)

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['guardduty'] = service
        self.display_progress(service, 'guardduty')
        if service['count'] > 0:
            self.active_services.append('guardduty')
        return

    def enumerate_inspector2(self):
        try:
            inspector2 = boto3.client('inspector2')
            response = try_except(inspector2.list_coverage)
            response.pop('ResponseMetadata', None)
            resources = response

            identifiers = []
            for el in resources.get('coveredResources', []):
                if 'AWS_ACCOUNT' != el['resourceType']:
                    identifiers.append(el['resourceId'])

            service = {'count': len(identifiers), 'identifiers': identifiers}
        except Exception as e:
            service = {'count': 0, 'data': [], 'identifiers': [str(e)]}
       
        self.services['inspector'] = service
        self.display_progress(service, 'inspector')
        if service['count'] > 0:
            self.active_services.append('inspector')
        return

    def enumerate_detective(self):
        detective = boto3.client('detective')
        response = try_except(detective.list_graphs)
        response.pop('ResponseMetadata', None)
        graphs = fix_json(response)

        identifiers = []
        for el in graphs.get('GraphList', []):
            identifiers.append(el['Arn'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['detective'] = service
        self.display_progress(service, 'detective')
        if service['count'] > 0:
            self.active_services.append('detective')
        return

    def enumerate_maciev2(self):
        macie2 = boto3.client('macie2')
        response = try_except(macie2.describe_buckets)
        response.pop('ResponseMetadata', None)
        buckets = fix_json(response)

        identifiers = []
        for el in buckets.get('buckets', []):
            identifiers.append(el['bucketArn'])

        service = {'count': len(identifiers), 'identifiers': identifiers}
        self.services['macie'] = service
        self.display_progress(service, 'macie')
        if service['count'] > 0:
            self.active_services.append('macie')
        return

    def display_progress(self, service, name, no_list = False):
        if service['count'] != 0:
            if no_list:
                print("\t\t\u2705 " + name.upper() + '\033[1m'+" - Available") 
            else:
                print("\t\t\u2705 " + name.upper() + '\033[1m'+" - Available with a count of " + str(service['count']) + '\033[0m'+ " and with the following identifiers: ") 
                for identity in service['identifiers']:
                    print("\t\t\t\u2022 " + identity)
        else:
            print("\t\t\u274c " + name.upper() + '\033[1m'+" - Not Available" + '\033[0m')

class Configuration:
    results = {}
    bucket = ''
    region = ''
    active_services = []

    def __init__(self, region):
        self.bucket = create_s3_if_not_exists(region, PREPARATION_BUCKET)
        self.active_services = []

    def self_test(self):
        print('Configuration works')

    def execute(self, active_services):
        print('Configuration')
        self.active_services = active_services

        self.get_configuration_s3()
        self.get_configuration_wafv2()
        self.get_configuration_lambda()
        self.get_configuration_vpc()
        self.get_configuration_elasticbeanstalk()

        self.get_configuration_route53()
        self.get_configuration_ec2()
        self.get_configuration_iam()
        self.get_configuration_dynamodb()
        self.get_configuration_rds()

        self.get_configuration_cloudwatch()
        self.get_configuration_guardduty()
        self.get_configuration_detective()
        self.get_configuration_inspector2()
        self.get_configuration_maciev2()
        self.get_configuration_cloudtrail()

        write_s3(self.bucket, CONFIGURATION_KEY, json.dumps(self.results, indent=4, default=str))
        return

    def get_configuration_s3(self):
        if 's3' not in self.active_services:
            self.display_progress(0, 's3')
            return
        s3 = boto3.client('s3')

        response = try_except(s3.list_buckets)
        response.pop('ResponseMetadata', None)
        buckets = fix_json(response)
        buckets = buckets.get('Buckets', [])

        objects = {}
        buckets_logging = {}
        buckets_policy = {}
        buckets_acl = {}
        buckets_location = {}
        for bucket in buckets:
            name = bucket['Name']
            objects[name] = []
            response = try_except(s3.list_objects_v2, Bucket=name)
            response.pop('ResponseMetadata', None)
            response = fix_json(response)
            objects[name].extend(response)
        
            response = try_except(s3.get_bucket_logging, Bucket=name)
            response.pop('ResponseMetadata', None)
            if 'LoggingEnabled' in response:
                buckets_logging[name] = response
            else:
                buckets_logging[name] = {'LoggingEnabled': False}

            response = try_except(s3.get_bucket_policy, Bucket=name)
            response.pop('ResponseMetadata', None)
            buckets_policy[name] = json.loads(response.get('Policy', '{}'))

            response = try_except(s3.get_bucket_acl, Bucket=name)
            response.pop('ResponseMetadata', None)
            buckets_acl[name] = response

            response = try_except(s3.get_bucket_location, Bucket=name)
            response.pop('ResponseMetadata', None)
            buckets_location[name] = response

        results = []
        results.append(create_command('aws s3api list-objects-v2 --bucket <name>', objects))
        results.append(create_command('aws s3api get-bucket-logging --bucket <name>', buckets_logging))
        results.append(create_command('aws s3api get-bucket-policy --bucket <name>', buckets_policy))
        results.append(create_command('aws s3api get-bucket-acl --bucket <name>', buckets_acl))
        results.append(create_command('aws s3api get-bucket-location --bucket <name>', buckets_location))

        self.results['s3'] = results
        self.display_progress(len(results), 's3')
        return

    def get_configuration_wafv2(self):
        if 'wafv2' not in self.active_services:
            self.display_progress(0, 'wafv2')
            return
        wafv2 = boto3.client('wafv2')

        response = try_except(wafv2.list_web_acls, Scope='REGIONAL')
        response.pop('ResponseMetadata', None)
        wafs = fix_json(response)
        wafs = wafs.get('WebACLs', [])

        logging_config = {}
        rule_groups = {}
        managed_rule_sets = {}
        ip_sets = {}
        resources = {}
        for waf in wafs:
            arn = waf['ARN']
            response = try_except(wafv2.get_logging_configuration, ResourceArn=arn)
            response.pop('ResponseMetadata', None)
            logging_config[arn] = response

            response = try_except(wafv2.list_rule_groups, Scope='REGIONAL')
            response.pop('ResponseMetadata', None)
            rule_groups[arn] = response

            response = try_except(wafv2.list_managed_rule_sets, Scope='REGIONAL')
            response.pop('ResponseMetadata', None)
            managed_rule_sets[arn] = response

            response = try_except(wafv2.list_ip_sets, Scope='REGIONAL')
            response.pop('ResponseMetadata', None)
            ip_sets[arn] = response

            response = try_except(wafv2.list_resources_for_web_acl, WebACLArn=arn)
            response.pop('ResponseMetadata', None)
            resources[arn] = response

        results = []
        results.append(create_command('aws wafv2 get-logging-configuration --resource-arn <arn>', logging_config))
        results.append(create_command('aws wafv2 list-rule-groups --scope REGIONAL', rule_groups))
        results.append(create_command('aws wafv2 list-managed-rule-sets --scope REGIONAL', managed_rule_sets))
        results.append(create_command('aws wafv2 list-ip-sets --scope REGIONAL', ip_sets))
        results.append(create_command('aws wafv2 list-resources-for-web-acl --resource-arn <arn>', resources))

        self.results['wafv2'] = results
        self.display_progress(len(results), 'wafv2')
        return

    def get_configuration_lambda(self):
        if 'lambda' not in self.active_services:
            self.display_progress(0, 'lambda')
            return
        lmbd = boto3.client('lambda')

        response = try_except(lmbd.list_functions)
        response.pop('ResponseMetadata', None)
        functions = response.get('Functions', [])

        function_config = {}
        for function in functions:
            name = function.get('FunctionName', '')
            if name == '':
                continue
            response = try_except(lmbd.get_function_configuration, FunctionName=name)
            response.pop('ResponseMetadata', None)
            function_config[name] = response

        response = try_except(lmbd.get_account_settings)
        response.pop('ResponseMetadata', None)
        account_settings = response

        response = try_except(lmbd.list_event_source_mappings)
        response.pop('ResponseMetadata', None)
        event_source_mappings = response

        results = []
        results.append(create_command('aws lambda get-function-configuration --function-name <name>', function_config))
        results.append(create_command('aws lambda get-account-settings', account_settings))
        results.append(create_command('aws lambda list-event-source-mappings', event_source_mappings))

        self.results['lambda'] = results
        self.display_progress(len(results), 'lambda')
        return

    def get_configuration_vpc(self):
        if 'vpc' not in self.active_services:
            self.display_progress(0, 'vpc')
            return
        ec2 = boto3.client('ec2')

        response = try_except(ec2.describe_vpcs)
        response.pop('ResponseMetadata', None)
        vpcs = response.get('Vpcs', [])

        dns_support = {}
        dns_hostnames = {}
        for vpc in vpcs:
            id = vpc.get('VpcId', '')
            if id == '':
                continue
            response = try_except(ec2.describe_vpc_attribute, VpcId=id, Attribute='enableDnsSupport')
            response.pop('ResponseMetadata', None)
            dns_support[id] = response

            response = try_except(ec2.describe_vpc_attribute, VpcId=id, Attribute='enableDnsHostnames')
            response.pop('ResponseMetadata', None)
            dns_hostnames[id] = response

        response = try_except(ec2.describe_flow_logs)
        response.pop('ResponseMetadata', None)
        flow_logs = response

        response = try_except(ec2.describe_vpc_peering_connections)
        response.pop('ResponseMetadata', None)
        peering_connections = response

        response = try_except(ec2.describe_vpc_endpoint_connections)
        response.pop('ResponseMetadata', None)
        endpoint_connections = response

        response = try_except(ec2.describe_vpc_endpoint_service_configurations)
        response.pop('ResponseMetadata', None)
        endpoint_service_config = response

        response = try_except(ec2.describe_vpc_classic_link)
        response.pop('ResponseMetadata', None)
        classic_links = response

        response = try_except(ec2.describe_vpc_endpoints)
        response.pop('ResponseMetadata', None)
        endpoints = response

        response = try_except(ec2.describe_local_gateway_route_table_vpc_associations)
        response.pop('ResponseMetadata', None)
        local_gateway_route_table = response

        results = []
        results.append(create_command('aws ec2 describe-vpc-attribute --vpc-id <id> --attribute enableDnsSupport', dns_support))
        results.append(create_command('aws ec2 describe-vpc-attribute --vpc-id <id> --attribute enableDnsHostnames', dns_hostnames))
        results.append(create_command('aws ec2 describe-flow-logs', flow_logs))
        results.append(create_command('aws ec2 describe-vpc-peering-connections', peering_connections))
        results.append(create_command('aws ec2 describe-vpc-endpoint-connections', endpoint_connections))
        results.append(create_command('aws ec2 describe-vpc-endpoint-service-configurations', endpoint_service_config))
        results.append(create_command('aws ec2 describe-vpc-classic-link', classic_links))
        results.append(create_command('aws ec2 describe-vpc-endpoints', endpoints))
        results.append(create_command('aws ec2 describe-local-gateway-route-table-vpc-associations', local_gateway_route_table))

        self.results['vpc'] = results
        self.display_progress(len(results), 'vpc')
        return

    def get_configuration_elasticbeanstalk(self):
        if 'elasticbeanstalk' not in self.active_services:
            self.display_progress(0, 'elasticbeanstalk')
            return
        eb = boto3.client('elasticbeanstalk')

        response = try_except(eb.describe_environments)
        response.pop('ResponseMetadata', None)
        environments = fix_json(response)
        environments = environments.get('Environments', [])
        
        resources = {}
        managed_actions = {}
        managed_action_history = {}
        instances_health = {}
        for environment in environments:
            id = environment.get('EnvironmentId', '')
            if id == '':
                continue
            resources[id] = []
            response = try_except(eb.describe_environment_resources, EnvironmentId=id)
            response.pop('ResponseMetadata', None)
            resources[id] = response

            managed_actions[id] = []
            response = try_except(eb.describe_environment_managed_actions, EnvironmentId=id)
            response.pop('ResponseMetadata', None)
            managed_actions[id] = response

            managed_action_history[id] = []
            response = try_except(eb.describe_environment_managed_action_history, EnvironmentId=id)
            response.pop('ResponseMetadata', None)
            managed_action_history[id] = response

            instances_health[id] = []
            response = try_except(eb.describe_instances_health, EnvironmentId=id)
            response.pop('ResponseMetadata', None)
            instances_health[id] = response

        response = try_except(eb.describe_applications)
        response.pop('ResponseMetadata', None)
        data = fix_json(response)
        applications = data

        response = try_except(eb.describe_account_attributes)
        response.pop('ResponseMetadata', None)
        data = response
        account_attributes = data

        results = []
        results.append(create_command('aws elasticbeanstalk describe-environment-resources --environment-id <id>', resources))
        results.append(create_command('aws elasticbeanstalk describe-environment-managed-actions --environment-id <id>', managed_actions))
        results.append(create_command('aws elasticbeanstalk describe-environment-managed-action-history --environment-id <id>', managed_action_history))
        results.append(create_command('aws elasticbeanstalk describe-instances-health --environment-id <id>', instances_health))
        results.append(create_command('aws elasticbeanstalk describe-environments', environments))
        results.append(create_command('aws elasticbeanstalk describe-applications', applications))
        results.append(create_command('aws elasticbeanstalk describe-account-attributes', account_attributes))

        self.results['eb'] = results
        self.display_progress(len(results), 'elasticbeanstalk')
        return

    def get_configuration_route53(self):
        if 'route53' not in self.active_services:
            self.display_progress(0, 'route53')
            return
        route53 = boto3.client('route53')
        route53resolver = boto3.client('route53resolver')

        response = try_except(route53.list_hosted_zones)
        response.pop('ResponseMetadata', None)
        hosted_zones = response.get('HostedZones', [])

        response = try_except(route53.list_traffic_policies)
        response.pop('ResponseMetadata', None)
        get_traffic_policies = response

        response = try_except(route53resolver.list_resolver_configs)
        response.pop('ResponseMetadata', None)
        resolver_configs = response

        response = try_except(route53resolver.list_firewall_configs)
        response.pop('ResponseMetadata', None)
        resolver_firewall_config = response

        response = try_except(route53resolver.list_resolver_query_log_configs)
        response.pop('ResponseMetadata', None)
        resolver_log_configs = response

        zones = []
        get_zones =[]
        results = []

        for el in hosted_zones:
            zones.append(el['Id'])
        for zone in zones:
            response = try_except(route53.get_hosted_zone, Id=zone)
            response.pop('ResponseMetadata', None)
            get_zones.append(response)

        results.append(create_command("aws route53 list-traffic-policies", get_traffic_policies))
        results.append(create_command("aws route53 get-hosted-zone --id <string>", get_zones))
        results.append(create_command("aws route53resolver list-resolver-configs", resolver_configs))
        results.append(create_command("aws route53resolver list-resolver-query-log-configs", resolver_log_configs))
        results.append(create_command("aws route53resolver list-firewall-configs ", resolver_firewall_config))

        self.results['route53'] = results
        self.display_progress(len(results), 'route53')
        return

    def get_configuration_ec2(self):
        if 'ec2' not in self.active_services:
            self.display_progress(0, 'ec2')
            return
        ec2 = boto3.client('ec2')

        response = try_except(ec2.describe_export_tasks)
        response.pop('ResponseMetadata', None)
        export = fix_json(response)

        response = try_except(ec2.describe_fleets)
        response.pop('ResponseMetadata', None)
        fleets = fix_json(response)

        response = try_except(ec2.describe_hosts)
        response.pop('ResponseMetadata', None)
        hosts = fix_json(response)

        response = try_except(ec2.describe_key_pairs)
        response.pop('ResponseMetadata', None)
        key_pairs = fix_json(response)

        response = try_except(ec2.describe_volumes)
        response.pop('ResponseMetadata', None)
        volumes = fix_json(response)

        response = try_except(ec2.describe_subnets)
        response.pop('ResponseMetadata', None)
        subnets = fix_json(response)

        response = try_except(ec2.describe_security_groups)
        response.pop('ResponseMetadata', None)
        sec_groups = fix_json(response)

        response = try_except(ec2.describe_route_tables)
        response.pop('ResponseMetadata', None)
        route_tables = fix_json(response)

        response = try_except(ec2.describe_snapshots)
        response.pop('ResponseMetadata', None)
        snapshots = fix_json(response)

        results= []
        results.append(create_command("aws ec2 describe-export-tasks", export))
        results.append(create_command("aws ec2 describe-fleets", fleets))
        results.append(create_command("aws ec2 describe-hosts", hosts))
        results.append(create_command("aws ec2 describe-key-pairs",key_pairs))
        results.append(create_command("aws ec2 describe-volumes", volumes))
        results.append(create_command("aws ec2 describe-subnets", subnets))
        results.append(create_command("aws ec2 describe-security-groups", sec_groups))
        results.append(create_command("aws ec2 describe-route-tables", route_tables))
        results.append(create_command("aws ec2 describe-snapshots", snapshots))

        self.results['ec2'] = results
        self.display_progress(len(results), 'ec2')
        return

    def get_configuration_iam(self):
        if 'iam' not in self.active_services:
            self.display_progress(0, 'iam')
            return
        iam = boto3.client('iam')

        response = try_except(iam.get_account_summary)
        response.pop('ResponseMetadata', None)
        get_summary = fix_json(response)

        response = try_except(iam.get_account_authorization_details)
        response.pop('ResponseMetadata', None)
        get_auth_details = fix_json(response)

        response = try_except(iam.list_ssh_public_keys)
        response.pop('ResponseMetadata', None)
        list_ssh_pub_keys = fix_json(response)

        response = try_except(iam.list_mfa_devices)
        response.pop('ResponseMetadata', None)
        list_mfa_devices = fix_json(response)

        results = []
        results.append(create_command("aws iam get-account-summary", get_summary))
        results.append(create_command("aws iam get-account-authorization-details", get_auth_details))
        results.append(create_command("aws iam list-ssh-public-keys  ", list_ssh_pub_keys))
        results.append(create_command("aws iam list-mfa-devices ", list_mfa_devices))

        self.results['iam'] = results
        self.display_progress(len(results), 'iam')
        return

    def get_configuration_dynamodb(self):
        if 'dynamodb' not in self.active_services:
            self.display_progress(0, 'dynamodb')
            return
        dynamodb = boto3.client('dynamodb')

        tables_info = []
        export_info = []

        backups = try_except(dynamodb.list_backups)
        backups.pop('ResponseMetadata', None)

        response = try_except(dynamodb.list_tables)
        response.pop('ResponseMetadata', None)
        list_tables = response.get('TableNames', [])

        response = try_except(dynamodb.list_exports)
        response.pop('ResponseMetadata', None)
        list_exports = response.get('ExportSummaries', [])
        
        for table in list_tables:
            response = try_except(dynamodb.describe_table, TableName=table)
            response.pop('ResponseMetadata', None)
            get_table = fix_json(response)
            tables_info.append(get_table)
        
        for export in list_exports:
            response = try_except(dynamodb.describe_export, ExportArn=export.get("ExportArn", ''))
            response.pop('ResponseMetadata', None)
            get_export = fix_json(response)
            export_info.append(get_export)

        results = []
        results.append(create_command("aws dynamodb list-backups", backups))
        results.append(create_command("aws dynamodb describe-table --table-name <name>", tables_info))
        results.append(create_command("aws dynamodb list-exports",  list_exports))
        results.append(create_command("aws dynamodb describe-export --export-arn <arn>", export_info))
        
        self.results['dynamodb'] = results
        self.display_progress(len(results), 'dynamodb')
        return

    def get_configuration_rds(self):
        if 'rds' not in self.active_services:
            self.display_progress(0, 'rds')
            return
        rds = boto3.client('rds')

        response = try_except(rds.describe_db_clusters)
        response.pop('ResponseMetadata', None)
        clusters = fix_json(response)

        response = try_except(rds.describe_db_snapshots)
        response.pop('ResponseMetadata', None)
        snapshots = fix_json(response)

        response = try_except(rds.describe_db_proxies)
        response.pop('ResponseMetadata', None)
        proxies = fix_json(response)

        results = []
        results.append(create_command("aws rds describe-db-clusters", clusters))
        results.append(create_command("aws rds describe-db-snapshots", snapshots))
        results.append(create_command("aws rds describe-db-proxies ", proxies))

        self.results['rds'] = results
        self.display_progress(len(results), 'rds')
        return

    def get_configuration_guardduty(self):
        if 'guardduty' not in self.active_services:
            self.display_progress(0, 'guardduty')
            return
        guardduty = boto3.client('guardduty')

        detectors = {}
        filters = {}
        filter_data = {}
        publishing_destinations = {}
        threat_intel = {}
        ip_sets = {}

        response = try_except(guardduty.list_detectors)
        response.pop('ResponseMetadata', None)
        detector_ids = response.get('DetectorIds', [])

        for detector in detector_ids:
            response = try_except(guardduty.get_detector, DetectorId=detector)
            response.pop('ResponseMetadata', None)
            detectors[detector] = response

            response = try_except(guardduty.list_filters, DetectorId=detector)
            response.pop('ResponseMetadata', None)
            filters[detector] = response
            filter_names = response['FilterNames']
            
            for filter_name in filter_names:
                filter_data[detector] = []
                response = try_except(guardduty.get_fitler, DetectorId=detector, FilterName=filter_name)
                response.pop('ResponseMetadata', None)
                filter_data[detector].extend(response)

            response = try_except(guardduty.list_publishing_destinations, DetectorId=detector)
            response.pop('ResponseMetadata', None)
            publishing_destinations[detector] = response

            response = try_except(guardduty.list_threat_intel_sets, DetectorId=detector)
            response.pop('ResponseMetadata', None)
            threat_intel[detector] = response

            response = try_except(guardduty.list_ip_sets, DetectorId=detector)
            response.pop('ResponseMetadata', None)
            ip_sets[detector] = response

        results = []
        results.append(create_command('guardduty get-detector --detector-id <id>', detectors))
        results.append(create_command('guardduty list-filters --detector-id <id>', filters))
        results.append(create_command('guardduty get-filter --detector-id <id> --filter-name <filter>', filter_data))
        results.append(create_command('guardduty list-publishing-destinations --detector-id <id>', publishing_destinations))
        results.append(create_command('guardduty list-threat-intel-sets --detector-id <id>', threat_intel))
        results.append(create_command('guardduty list-ip-sets --detector-id <id>', ip_sets))

        self.results['guardduty'] = results
        self.display_progress(len(results), 'guardduty')
        return

    def get_configuration_cloudwatch(self):
        if 'cloudwatch' not in self.active_services:
            self.display_progress(0, 'cloudwatch')
            return
        cloudwatch = boto3.client('cloudwatch')

        response = try_except(cloudwatch.list_dashboards)
        response.pop('ResponseMetadata', None)
        dashboards = fix_json(response)
        dashboards = dashboards.get('DashboardEntries', [])

        dashboards_data = {}
        for dashboard in dashboards:
            dashboard_name = dashboard.get('DashboardName', '')
            if dashboard_name == '':
                continue
            response = try_except(cloudwatch.get_dashboard, DashboardName=dashboard_name)
            response.pop('ResponseMetadata', None)
            dashboards_data[dashboard_name] = response
        
        response = try_except(cloudwatch.list_metrics)
        response.pop('ResponseMetadata', None)
        metrics = response

        results = []
        results.append(create_command('aws cloudwatch get-dashboard --name <name>', dashboards_data))
        results.append(create_command('aws cloudwatch list-metrics --name <name>', metrics))

        self.results['cloudwatch'] = results
        self.display_progress(len(results), 'cloudwatch')
        return

    def get_configuration_maciev2(self):
        if 'macie' not in self.active_services:
            self.display_progress(0, 'macie')
            return
        macie2 = boto3.client('macie2')

        response = try_except(macie2.get_finding_statistics, groupBy="type")
        response.pop('ResponseMetadata', None)
        statistics_severity = fix_json(response)

        response = try_except(macie2.get_finding_statistics, groupBy="severity.description")
        response.pop('ResponseMetadata', None)
        statistics_type = fix_json(response)

        results = []
        results.append(create_command("aws macie2 get-finding-statistics --group-by severity.description", statistics_severity))
        results.append(create_command("aws macie2 get-finding-statistics --group-by type", statistics_type))

        self.results['macie'] = results
        self.display_progress(len(results), 'macie')
        return

    def get_configuration_inspector2(self):
        if 'inspector' not in self.active_services:
            self.display_progress(0, 'inspector')
            return
        inspector2 = boto3.client('inspector2')

        response = try_except(inspector2.list_coverage)
        response.pop('ResponseMetadata', None)
        coverage = fix_json(response)

        response = try_except(inspector2.list_usage_totals)
        response.pop('ResponseMetadata', None)
        usage = fix_json(response)

        response = try_except(inspector2.list_account_permissions)
        response.pop('ResponseMetadata', None)
        permission = fix_json(response)

        results = []
        results.append(create_command("aws inspector2 list-coverage", coverage))
        results.append(create_command("aws inspector2 list-usage-totals", usage))
        results.append(create_command("aws inspector2 list-account-permissions", permission))

        self.results['inspector'] = results
        self.display_progress(len(results), 'inspector')
        return

    def get_configuration_detective(self):
        if 'detective' not in self.active_services:
            self.display_progress(0, 'detective')
            return
        detective = boto3.client('detective')

        response = try_except(detective.list_graphs)
        response.pop('ResponseMetadata', None)
        graphs = fix_json(response)

        results = []
        results.append(create_command("aws detective list-graphs ", graphs))

        self.results['detective'] = results
        self.display_progress(len(results), 'detective')
        return

    def get_configuration_cloudtrail(self):
        if 'cloudtrail' not in self.active_services:
            self.display_progress(0, 'cloudtrail')
            return
        ct = boto3.client('cloudtrail')

        response = try_except(ct.list_trails)
        response.pop('ResponseMetadata', None)
        trails = fix_json(response)

        trails_data = {}
        for trail in trails['Trails']:
            trail_name = trail.get('Name', '')
            if trail_name == '':
                continue
            response = try_except(ct.get_trail, Name=trail_name)
            response.pop('ResponseMetadata', None)
            trails_data[trail_name] = fix_json(response)

        results = []
        results.append(create_command("aws cloudtrail list-trails", trails))
        results.append(create_command("aws cloudtrail get-trail --name <name>", trails_data))

        self.results['cloudtrail'] = results
        self.display_progress(len(results), 'cloudtrail')
        return

    def display_progress(self, count, name):
        if count != 0:
            print("         \u2705 " + name.upper() + '\033[1m'+" - JSON File Extracted " + '\033[0m') 
        else:
            print("         \u274c " + name.upper() + '\033[1m'+" - No Configuration" + '\033[0m')

class Logs:
    bucket = ''
    region = ''
    active_services = []

    def __init__(self, region):
        self.bucket = create_s3_if_not_exists(region, LOGS_BUCKET)
        self.active_services = []

    def self_test(self):
        print('Logs work')

    def execute(self, active_services):
        print('Log Extraction')
        self.active_services = active_services

        self.get_logs_s3()
        self.get_logs_wafv2()
        self.get_logs_vpc()
        self.get_logs_elasticbeanstalk()

        self.get_logs_route53()
        self.get_logs_ec2()
        self.get_logs_rds()

        self.get_logs_cloudwatch()
        self.get_logs_guardduty()
        self.get_logs_inspector2()
        self.get_logs_maciev2()

        self.get_logs_cloudtrail_logs()
        self.get_logs_cloudtrail_trails()
        
        return

    def get_logs_guardduty(self):
        if 'guardduty' not in self.active_services:
            self.display_progress(0, 'guardduty')
            return
        guardduty = boto3.client('guardduty')

        response = try_except(guardduty.list_detectors)
        detector_ids = response.get('DetectorIds', [])

        findings_data = {}
        for detector in detector_ids:
            findings = try_except(guardduty.list_findings, DetectorId=detector)
            findings = findings['FindingIds']

            response = try_except(guardduty.get_findings, DetectorId=detector, FindingIds=findings)
            response.pop('ResponseMetadata', None)
            response = fix_json(response)
            findings_data[detector] = response

        results = []
        results.append(create_command('guardduty get-findings --detector-id <id> --findings-id <ids>', findings_data))

        self.display_progress(len(results), 'guardduty')
        write_s3(self.bucket, LOGS_KEY + 'guardduty/guardduty.json', json.dumps(results, indent=4, default=str))
        return

    def cloudtrail_lookup(self, token = None):
        ct = boto3.client('cloudtrail')
        if token is None:
            response = ct.lookup_events(
                MaxResults=50,
            )
        else:
            response = ct.lookup_events(
                MaxResults=50,
                NextToken=token,
            )
        return response

    def get_logs_cloudtrail_logs(self):
        if 'cloudtrail-logs' not in self.active_services:
            self.display_progress(0, 'cloudtrail-logs')
            return
        response = self.cloudtrail_lookup()
        events = response["Events"]
        token = response.get('NextToken')
        while token:
            response = self.cloudtrail_lookup(token)
            events.extend(response["Events"])
            token = response.get('NextToken')

        response['Events'] = events
        logs = fix_json(response)
        write_s3(self.bucket, LOGS_KEY + 'cloudtrail/cloudtrail.json', json.dumps(logs, indent=4, default=str))
        self.display_progress(1, 'cloudtrail-logs')

    def get_logs_cloudtrail_trails(self):
        if 'cloudtrail-trails' not in self.active_services:
            self.display_progress(0, 'cloudtrail-trails')
            return
        ct = boto3.client('cloudtrail')
        response = try_except(ct.list_trails)
        trails = response["Trails"]
        
        for trail in trails:
            if not 'Name' in trail:
                continue
            trail_name = trail['Name']
            response = try_except(ct.get_trail, Name=trail_name)
            if 'Trail' not in response or 'S3BucketName' not in response['Trail']:
                continue
            src_bucket = response['Trail']['S3BucketName']
            self.copy_s3_bucket(src_bucket, self.bucket, 'cloudtrail/' + trail_name)

        self.display_progress(1, 'cloudtrail-trails')
        return

    def get_logs_wafv2(self):
        if 'wafv2' not in self.active_services:
            self.display_progress(0, 'wafv2')
            return
        wafv2 = boto3.client('wafv2')

        response = try_except(wafv2.list_web_acls, Scope='REGIONAL')
        wafs = response.get('WebACLs', [])
        cnt = 0

        for waf in wafs:
            arn = waf['ARN']
            logging = try_except(wafv2.get_logging_configuration, ResourceArn=arn)
            if 'LoggingConfiguration' in logging:
                destinations = logging['LoggingConfiguration']['LogDestinationConfigs']
                for destination in destinations:
                    if 's3' in destination:
                        bucket = destination.split(':')[-1]
                        src_bucket = bucket.split('/')[0]
                        self.copy_s3_bucket(src_bucket, self.bucket, 'wafv2')
                        cnt += 1
        self.display_progress(cnt, 'wafv2')

    def get_logs_vpc(self):
        if 'vpc' not in self.active_services:
            self.display_progress(0, 'vpc')
            return
        ec2 = boto3.client('ec2')
        response = try_except(ec2.describe_flow_logs)
        flow_logs = response.get("FlowLogs", [])
        cnt = 0

        for flow_log in flow_logs:
            if "s3" in flow_log["LogDestinationType"]:
                bucket = flow_log["LogDestination"].split(':')[-1]
                src_bucket = bucket.split('/')[0]
                self.copy_s3_bucket(src_bucket, self.bucket, 'vpc')
                cnt += 1
        self.display_progress(cnt, 'vpc')

    def get_logs_elasticbeanstalk(self):
        if 'elasticbeanstalk' not in self.active_services:
            self.display_progress(0, 'elasticbeanstalk')
            return
        eb = boto3.client('elasticbeanstalk')

        response = try_except(eb.describe_environments)
        environments = response.get('Environments', [])

        for environment in environments:
            name = environment.get('EnvironmentName', '')
            if name == '':
                continue

            response = try_except(eb.request_environment_info, EnvironmentName=name, InfoType='bundle')
            response = fix_json(response)
            time.sleep(60)

            response = try_except(eb.retrieve_environment_info, EnvironmentName=name, InfoType='bundle')
            response = fix_json(response)

            urls = response['EnvironmentInfo']
            if len(urls) > 0:
                url = urls[-1]
                url = url['Message']

            filename = name + '.zip'
            r = requests.get(url)
            with open(filename, 'wb') as f:
                f.write(r.content)
            
            key = 'eb/' + name + '.zip'
            writefile_s3(self.bucket, key, filename)
            os.remove(filename)
        
        self.display_progress(len(environments), 'elasticbeanstalk')
        return

    def get_logs_cloudwatch(self):
        if 'cloudwatch' not in self.active_services:
            self.display_progress(0, 'cloudwatch')
            return
        cloudwatch = boto3.client('cloudwatch')

        response = try_except(cloudwatch.list_dashboards)
        dashboards = response.get('DashboardEntries', [])

        dashboards_data = {}
        for dashboard in dashboards:
            dashboard_name = dashboard.get('DashboardName', '')
            if dashboard_name == '':
                continue
            response = try_except(cloudwatch.get_dashboard, DashboardName=dashboard_name)
            response.pop('ResponseMetadata', None)
            dashboards_data[dashboard_name] = fix_json(response)

        response = try_except(cloudwatch.list_metrics)
        response.pop('ResponseMetadata', None)
        metrics = fix_json(response)

        response = try_except(cloudwatch.describe_alarms)
        response.pop('ResponseMetadata', None)
        alarms = fix_json(response)

        results = []
        results.append(create_command('cloudwatch get-dashboard --name <name>', dashboards_data))
        results.append(create_command('cloudwatch list-metrics --name <name>', metrics))
        results.append(create_command('cloudwatch describe-alarms --name <name>', alarms))

        self.display_progress(len(results), 'cloudwatch')
        write_s3(self.bucket, LOGS_KEY + 'cloudwatch/cloudwatch.json', json.dumps(results, indent=4, default=str))
        return

    def copy_s3_bucket(self, src_bucket, dst_bucket, key_part):
        s3res = boto3.resource('s3')
        s3api = boto3.client('s3')

        response = try_except(s3api.list_objects_v2, Bucket=src_bucket)
        contents = response.get('Contents', [])

        for key in contents:
            copy_source = {
                'Bucket': src_bucket,
                'Key': key['Key']
            }
            new_key = LOGS_KEY + key_part + '/' + src_bucket + '/' + key['Key']
            try_except(s3res.meta.client.copy, copy_source, dst_bucket, new_key)

    def get_logs_s3(self):
        if 's3' not in self.active_services:
            self.display_progress(0, 's3')
            return
        s3 = boto3.client('s3')

        response = try_except(s3.list_buckets)
        response.pop('ResponseMetadata', None)
        buckets = fix_json(response)
        buckets = buckets.get('Buckets', [])
        cnt = 0

        for bucket in buckets:
            name = bucket.get('Name', '')
            if name == '':
                continue

            logging = try_except(s3.get_bucket_logging, Bucket=name)
            if 'LoggingEnabled' in logging:
                target = logging['LoggingEnabled']['TargetBucket']
                bucket = target.split(':')[-1]
                src_bucket = bucket.split('/')[0]
                self.copy_s3_bucket(src_bucket, self.bucket, 's3')
                cnt += 1

        self.display_progress(cnt, 's3')
        return

    def get_logs_inspector2(self):
        if 'inspector' not in self.active_services:
            self.display_progress(0, 'inspector')
            return
        inspector2 = boto3.client('inspector2')

        response = try_except(inspector2.list_findings)
        response.pop('ResponseMetadata', None)
        get_findings = fix_json(response)

        response = try_except(inspector2.list_finding_aggregations, aggregationType="TITLE")
        response.pop('ResponseMetadata', None)
        get_grouped_findings = fix_json(response)

        results = []
        results.append(create_command("aws inspector2 list-findings", get_findings))
        results.append(create_command("aws inspector2 list-finding-aggregations --aggregation-type TITLE" , get_grouped_findings))

        self.display_progress(len(results), 'inspector')
        write_s3(self.bucket, LOGS_KEY + 'inspector/inspector.json', json.dumps(results, indent=4, default=str))
        return

    def get_logs_maciev2(self):
        if 'macie' not in self.active_services:
            self.display_progress(0, 'macie')
            return
        macie2 = boto3.client('macie2')

        response = try_except(macie2.list_findings)
        response.pop('ResponseMetadata', None)
        get_list_findings = fix_json(response)

        response = try_except(macie2.get_findings, findingIds=get_list_findings.get("findingIds", []))
        response.pop('ResponseMetadata', None)
        findings = fix_json(response)

        results = []
        results.append(create_command("aws macie2 list-findings", get_list_findings))
        results.append(create_command("aws macie2 get-findings --finding-ids <ID>" , findings))

        self.display_progress(len(results), 'macie')
        write_s3(self.bucket, LOGS_KEY + 'macie/macie.json', json.dumps(results, indent=4, default=str))
        return

    def create_json(self):
        file_json = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        }

        with open("role.json", 'w') as f:
            json.dump(file_json, f)
        with open("role.json", 'r') as fr:
            data = fr.read()

        return data

    def create_ssm_role(self):
        data = self.create_json()
        iam = boto3.client("iam")
        role_name = "SSM_IR_Extraction01" 
        instance_name = "SSM_S3_IR_Extraction01"

        try:
            new_role = iam.create_role(RoleName=role_name,Path= "/./",AssumeRolePolicyDocument=data)

            policy_ssm = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
            )

            policy_s3 = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess"
            )
        except Exception as e:
            if "EntityAlreadyExists" in str(e):
                pass
        try:
            create_instance_profile = iam.create_instance_profile(InstanceProfileName= instance_name)
            attach_role = iam.add_role_to_instance_profile(RoleName= role_name, InstanceProfileName= instance_name)
        except Exception as e:
            if "EntityAlreadyExists" in str(e):
                create_instance_profile = iam.get_instance_profile(InstanceProfileName=instance_name)

        profile_for_replace = {}
        profile_for_replace["Arn"]= create_instance_profile["InstanceProfile"]["Arn"]
        profile_for_replace["Name"]= create_instance_profile["InstanceProfile"]['InstanceProfileName']
        os.remove('role.json')

        return profile_for_replace

    def associate_role(self, instanceid, instance_prof):
        ec2 = boto3.client('ec2')
        string = ""+instance_prof["Name"]+""
        associate_prof = ec2.associate_iam_instance_profile(InstanceId=instanceid, IamInstanceProfile= {"Name": string})

    def extract_role_and_id(self):
        ec2 = boto3.client('ec2')
        list_instances_profiles = ec2.describe_iam_instance_profile_associations()
        old_profiles = []
        profile = {}
        prof = {}
        
        for instance in list_instances_profiles["IamInstanceProfileAssociations"]:
            profile["instanceID"] = instance['InstanceId']
            prof["Arn"] = instance['IamInstanceProfile']["Arn"]
            prof["Name"] = instance['IamInstanceProfile']["Arn"].split("/")[1].strip()
            profile["profileARN"] = prof
            profile["AssociatedID"] = instance["AssociationId"]
            old_profiles.append(profile)
            profile = {}
            prof={}

        return old_profiles  

    def replace_role(self, iam_profile, associate_id):
        ec2 = boto3.client('ec2')
        new_profile = ec2.replace_iam_instance_profile_association(
            IamInstanceProfile=iam_profile,
            AssociationId = associate_id)

        return new_profile

    def extract_list_ssm_instances(self):
        ssm = boto3.client('ssm')
        ssm_instances = ssm.describe_instance_information()
        total_ssm_instances = []

        for instance in  ssm_instances["InstanceInformationList"]:
            total_ssm_instances.append(instance["InstanceId"])

        return total_ssm_instances

    def extract_logs(self):
        ssm = boto3.client('ssm')
        list_of_logs = ["cat /var/log/syslog", 
        "cat /var/log/messages",
        "cat /var/log/auth.log",
        "cat /var/log/secure",
        "cat /var/log/boot.log",
        "cat /var/log/dmesg",
        "cat /var/log/faillog",
        "cat /var/log/cron",
        "cat /var/log/kern.log"]

        total_ssm_instances = self.extract_list_ssm_instances()
        send_command = ssm.send_command(
            InstanceIds = total_ssm_instances,
            DocumentName='AWS-RunShellScript',
            OutputS3BucketName=self.bucket,
            OutputS3KeyPrefix='ec2',
            Parameters={'commands': list_of_logs})

    def switch_profiles(self, old_profiles, fields, IamInstanceProfile):
        for profile in old_profiles:
            if fields["InstanceId"] == profile["instanceID"]:
                self.replace_role(IamInstanceProfile, profile["AssociatedID"])

    def new_profiles_instances(self, profiles, instances, IamInstanceProfile):
        for instance in instances["Reservations"]:
            for fields in instance["Instances"]:
                if "IamInstanceProfile" in fields:
                    self.switch_profiles(profiles, fields, IamInstanceProfile)
                else:
                    self.associate_role(fields["InstanceId"], IamInstanceProfile)

    def back_to_normal(self, old_profiles, new_profiles):
        for old_profile in old_profiles:
            for new_profile in new_profiles:
                if old_profile["instanceID"] == new_profile["instanceID"]:
                    self.replace_role(old_profile["profileARN"], new_profile["AssociatedID"])

    def get_logs_ec2(self):
        if 'ec2' not in self.active_services:
            self.display_progress(0, 'ec2')
            return
        profile_for_replace = self.create_ssm_role()
        time.sleep(60)
        ec2 = boto3.client('ec2')
        instances = ec2.describe_instances()
        old_profiles = self.extract_role_and_id()
        self.new_profiles_instances(old_profiles, instances, profile_for_replace)
        time.sleep(60)
        self.extract_logs()
        new_profiles = self.extract_role_and_id()
        self.back_to_normal(old_profiles, new_profiles)
        self.display_progress(1, 'ec2')

    def download_rds(self, nameDB, rds, logname):
        response = try_except(rds.download_db_log_file_portion,
            DBInstanceIdentifier=nameDB,
            LogFileName=logname,
            Marker='0'
        )
        
        return response.get("LogFileData", '')

    def get_logs_rds(self):
        if 'rds' not in self.active_services:
            self.display_progress(0, 'rds')
            return
        rds = boto3.client("rds")

        response = try_except(rds.describe_db_instances)
        list_of_dbs = response.get("DBInstances", [])
        total_logs = []

        for db in list_of_dbs:
            total_logs.append(self.download_rds(db["DBInstanceIdentifier"], rds,'external/mysql-external.log'))
            total_logs.append(self.download_rds(db["DBInstanceIdentifier"], rds,'error/mysql-error.log'))

        self.display_progress(len(list_of_dbs), 'rds')
        write_s3(self.bucket, LOGS_KEY + 'rds/rds.json', json.dumps(total_logs, indent=4, default=str))
        return

    def get_logs_route53(self):
        if 'route53' not in self.active_services:
            self.display_progress(0, 'route53')
            return
        route53resolver = boto3.client('route53resolver')
        response = try_except(route53resolver.list_resolver_query_log_configs)
        resolver_log_configs = response.get("ResolverQueryLogConfigs", [])
        cnt = 0

        for bucket_location in resolver_log_configs:
            if "s3" in bucket_location["DestinationArn"]:
                bucket = bucket_location["DestinationArn"].split(':')[-1]
                src_bucket = bucket.split('/')[0]
                self.copy_s3_bucket(src_bucket, self.bucket, 'route53')
                cnt += 1
        self.display_progress(cnt, 'route53')

    def display_progress(self, count, name):
        if count != 0:
            print("         \u2705 " + name.upper() + '\033[1m'+" - Logs extracted to S3 bucket " + '\033[0m') 
        else:
            print("         \u274c " + name.upper() + '\033[1m'+" - No Logs" + '\033[0m')

class IR:
    services = {}
    e = None
    c = None
    l = None
    active_services = []

    def __init__(self, region):
        self.e = Enumeration(region)
        self.c = Configuration(region)
        self.l = Logs(region)
        self.active_services = []

    def test_modules(self):
        self.e.self_test()
        self.c.self_test()
        self.l.self_test()

    def execute_enumeration(self):
        self.active_services = self.e.execute()

    def execute_configuration(self):
        self.c.execute(self.active_services)

    def execute_logs(self):
        self.l.execute(self.active_services)

def main():
    print('''
      _            _      _                                      
     (_)          (_)    | |                                     
      _ _ ____   ___  ___| |_ _   _ ___ ______ __ ___      _____ 
     | | '_ \ \ / / |/ __| __| | | / __|______/ _` \ \ /\ / / __|
     | | | | \ V /| | (__| |_| |_| \__ \     | (_| |\ V  V /\__ \\
     |_|_| |_|\_/ |_|\___|\__|\__,_|___/      \__,_| \_/\_/ |___/
                                                             
                                                             
     Copyright (c) 2022 Invictus Incident Response
     Authors: Antonio Macovei & Rares Bratean

    ''')
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', type=str)
    args = parser.parse_args()
    region = args.region
    if region is None:
        print("Error: Invalid syntax\n\t--region=<aws_region> is required to run the script")
        sys.exit(-1)
    ir = IR(region)
    # ir.test_modules()
    ir.execute_enumeration()
    ir.execute_configuration()
    ir.execute_logs()

if __name__ == "__main__":
    main()
