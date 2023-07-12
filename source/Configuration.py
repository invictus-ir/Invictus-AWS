import boto3

from source.utils import *


class Configuration:
    results = {}
    bucket = ""
    region = ""
    services = {}

    def __init__(self, region, dl):
        if dl:
            print("ff")
        else:
            # self.bucket = create_s3_if_not_exists(region, PREPARATION_BUCKET)
            print("==")

    def self_test(self):
        print("Configuration works")

    def execute(self, services):
        print("Configuration")
        self.services = services

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
        #
        # write_s3(
        #    self.bucket,
        #    CONFIGURATION_KEY,
        #    json.dumps(self.results, indent=4, default=str),
        # )

    def get_configuration_s3(self):
        s3_list = self.services["s3"]

        if s3_list["count"] == -1:
            # if no listing of the s3 buckets was done before
            response = try_except(S3_CLIENT.list_buckets)  # buckets' listing
            response.pop("ResponseMetadata", None)
            buckets = fix_json(response)
            elements = buckets.get("Buckets", [])

            if len(elements) == 0:
                self.display_progress(0, "s3")
                return

        elif s3_list["count"] == 0:
            # if there is not bucket at all
            self.display_progress(0, "s3")
            return
        else:
            elements = s3_list["elements"]

        objects = {}
        buckets_logging = {}
        buckets_policy = {}
        buckets_acl = {}
        buckets_location = {}

        for bucket in elements:
            bucket_name = bucket["Name"]
            objects[bucket_name] = []
            response = try_except(
                S3_CLIENT.list_objects_v2, Bucket=bucket_name
            )  # getting objects of each bucket
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            objects[bucket_name] = response

            response = try_except(S3_CLIENT.get_bucket_logging, Bucket=bucket_name)
            response.pop("ResponseMetadata", None)
            if "LoggingEnabled" in response:
                buckets_logging[bucket_name] = response
            else:
                buckets_logging[bucket_name] = {"LoggingEnabled": False}

            response = try_except(S3_CLIENT.get_bucket_policy, Bucket=bucket_name)
            response.pop("ResponseMetadata", None)
            buckets_policy[bucket_name] = json.loads(response.get("Policy", "{}"))

            response = try_except(S3_CLIENT.get_bucket_acl, Bucket=bucket_name)
            response.pop("ResponseMetadata", None)
            buckets_acl[bucket_name] = response

            response = try_except(S3_CLIENT.get_bucket_location, Bucket=bucket_name)
            response.pop("ResponseMetadata", None)
            buckets_location[bucket_name] = response

        results = []
        results.append(
            create_command("aws s3api list-objects-v2 --bucket <name>", objects)
        )
        results.append(
            create_command(
                "aws s3api get-bucket-logging --bucket <name>", buckets_logging
            )
        )
        results.append(
            create_command(
                "aws s3api get-bucket-policy --bucket <name>", buckets_policy
            )
        )
        results.append(
            create_command("aws s3api get-bucket-acl --bucket <name>", buckets_acl)
        )
        results.append(
            create_command(
                "aws s3api get-bucket-location --bucket <name>", buckets_location
            )
        )
        self.results["s3"] = results
        self.display_progress(len(results), "s3")
        return

    def get_configuration_wafv2(self):
        waf_list = self.services["wafv2"]

        if waf_list["count"] == -1:
            response = try_except(WAF_CLIENT.list_web_acls, Scope="REGIONAL")
            response.pop("ResponseMetadata", None)
            wafs = response.get("WebACLs", [])

            identifiers = []
            for el in wafs:
                identifiers.append(el["ARN"])

            if len(identifiers) == 0:
                self.display_progress(0, "wafv2")
                return

        elif waf_list["count"] == 0:
            self.display_progress(0, "wafv2")
            return
        else:
            identifiers = waf_list["ids"]

        logging_config = {}
        rule_groups = {}
        managed_rule_sets = {}
        ip_sets = {}
        resources = {}

        for arn in identifiers:
            response = try_except(WAF_CLIENT.get_logging_configuration, ResourceArn=arn)
            response.pop("ResponseMetadata", None)
            logging_config[arn] = response

            response = try_except(WAF_CLIENT.list_rule_groups, Scope="REGIONAL")
            response.pop("ResponseMetadata", None)
            rule_groups[arn] = response

            response = try_except(WAF_CLIENT.list_managed_rule_sets, Scope="REGIONAL")
            response.pop("ResponseMetadata", None)
            managed_rule_sets[arn] = response

            response = try_except(WAF_CLIENT.list_ip_sets, Scope="REGIONAL")
            response.pop("ResponseMetadata", None)
            ip_sets[arn] = response

            response = try_except(WAF_CLIENT.list_resources_for_web_acl, WebACLArn=arn)
            response.pop("ResponseMetadata", None)
            resources[arn] = response

        results = []
        results.append(
            create_command(
                "aws wafv2 get-logging-configuration --resource-arn <arn>",
                logging_config,
            )
        )
        results.append(
            create_command("aws wafv2 list-rule-groups --scope REGIONAL", rule_groups)
        )
        results.append(
            create_command(
                "aws wafv2 list-managed-rule-sets --scope REGIONAL", managed_rule_sets
            )
        )
        results.append(
            create_command("aws wafv2 list-ip-sets --scope REGIONAL", ip_sets)
        )
        results.append(
            create_command(
                "aws wafv2 list-resources-for-web-acl --resource-arn <arn>", resources
            )
        )

        self.results["wafv2"] = results
        print(results)
        self.display_progress(len(results), "wafv2")
        return

    def get_configuration_lambda(self):
        lambda_list = self.services["lambda"]

        if lambda_list["count"] == -1:
            response = try_except(LAMBDA_CLIENT.list_functions)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            functions = response.get("Functions", [])

            identifiers = []
            for function in functions:
                identifiers.append(function["FunctionName"])

            if len(identifiers) == 0:
                self.display_progress(0, "lambda")
                return

        elif lambda_list["count"] == 0:
            self.display_progress(0, "lambda")
            return
        else:
            identifiers = lambda_list["ids"]

        function_config = {}

        for name in identifiers:
            if name == "":
                continue
            response = try_except(
                LAMBDA_CLIENT.get_function_configuration, FunctionName=name
            )
            response.pop("ResponseMetadata", None)
            function_config[name] = response

        response = try_except(LAMBDA_CLIENT.get_account_settings)
        response.pop("ResponseMetadata", None)
        account_settings = response

        response = try_except(LAMBDA_CLIENT.list_event_source_mappings)
        response.pop("ResponseMetadata", None)
        event_source_mappings = response

        results = []
        results.append(
            create_command(
                "aws lambda get-function-configuration --function-name <name>",
                function_config,
            )
        )
        results.append(
            create_command("aws lambda get-account-settings", account_settings)
        )
        results.append(
            create_command(
                "aws lambda list-event-source-mappings", event_source_mappings
            )
        )

        self.results["lambda"] = results
        self.display_progress(len(results), "lambda")
        return

    def get_configuration_vpc(self):
        vpc_list = self.services["vpc"]

        if vpc_list["count"] == -1:
            response = try_except(EC2_CLIENT.describe_vpcs)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            vpcs = response.get("Vpcs", [])

            identifiers = []
            for vpc in vpcs:
                identifiers.append(vpc["VpcId"])

            if len(identifiers) == 0:
                self.display_progress(0, "vpc")
                return

        elif vpc_list["count"] == 0:
            self.display_progress(0, "vpc")
            return
        else:
            identifiers = vpc_list["ids"]

        dns_support = {}
        dns_hostnames = {}

        for id in identifiers:
            if id == "":
                continue
            response = try_except(
                EC2_CLIENT.describe_vpc_attribute,
                VpcId=id,
                Attribute="enableDnsSupport",
            )
            response.pop("ResponseMetadata", None)
            dns_support[id] = response

            response = try_except(
                EC2_CLIENT.describe_vpc_attribute,
                VpcId=id,
                Attribute="enableDnsHostnames",
            )
            response.pop("ResponseMetadata", None)
            dns_hostnames[id] = response

        response = try_except(EC2_CLIENT.describe_flow_logs)
        response.pop("ResponseMetadata", None)
        flow_logs = response

        response = try_except(EC2_CLIENT.describe_vpc_peering_connections)
        response.pop("ResponseMetadata", None)
        peering_connections = response

        response = try_except(EC2_CLIENT.describe_vpc_endpoint_connections)
        response.pop("ResponseMetadata", None)
        endpoint_connections = response

        response = try_except(EC2_CLIENT.describe_vpc_endpoint_service_configurations)
        response.pop("ResponseMetadata", None)
        endpoint_service_config = response

        response = try_except(EC2_CLIENT.describe_vpc_classic_link)
        response.pop("ResponseMetadata", None)
        classic_links = response

        response = try_except(EC2_CLIENT.describe_vpc_endpoints)
        response.pop("ResponseMetadata", None)
        endpoints = response

        response = try_except(
            EC2_CLIENT.describe_local_gateway_route_table_vpc_associations
        )
        response.pop("ResponseMetadata", None)
        local_gateway_route_table = response

        results = []
        results.append(
            create_command(
                "aws ec2 describe-vpc-attribute --vpc-id <id> --attribute enableDnsSupport",
                dns_support,
            )
        )
        results.append(
            create_command(
                "aws ec2 describe-vpc-attribute --vpc-id <id> --attribute enableDnsHostnames",
                dns_hostnames,
            )
        )
        results.append(create_command("aws ec2 describe-flow-logs", flow_logs))
        results.append(
            create_command(
                "aws ec2 describe-vpc-peering-connections", peering_connections
            )
        )
        results.append(
            create_command(
                "aws ec2 describe-vpc-endpoint-connections", endpoint_connections
            )
        )
        results.append(
            create_command(
                "aws ec2 describe-vpc-endpoint-service-configurations",
                endpoint_service_config,
            )
        )
        results.append(
            create_command("aws ec2 describe-vpc-classic-link", classic_links)
        )
        results.append(create_command("aws ec2 describe-vpc-endpoints", endpoints))
        results.append(
            create_command(
                "aws ec2 describe-local-gateway-route-table-vpc-associations",
                local_gateway_route_table,
            )
        )

        self.results["vpc"] = results
        self.display_progress(len(results), "vpc")
        return

    def get_configuration_elasticbeanstalk(self):
        eb_list = self.services["elasticbeanstalk"]

        if eb_list["count"] == -1:
            response = try_except(EB_CLIENT.describe_environments)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            environments = response.get("Environments", [])

            identifiers = []
            for env in environments:
                identifiers.append(env["EnvironmentId"])

            if len(identifiers) == 0:
                self.display_progress(0, "elasticbeanstalk")
                return

        elif eb_list["count"] == 0:
            self.display_progress(0, "elasticbeanstalk")
            return
        else:
            identifiers = []
            elements = eb_list["elements"]
            for el in elements:
                identifiers.append(el["EnvironmentId"])

        resources = {}
        managed_actions = {}
        managed_action_history = {}
        instances_health = {}

        for id in identifiers:
            if id == "":
                continue
            resources[id] = []
            response = try_except(
                EB_CLIENT.describe_environment_resources, EnvironmentId=id
            )
            response.pop("ResponseMetadata", None)
            resources[id] = response

            managed_actions[id] = []
            response = try_except(
                EB_CLIENT.describe_environment_managed_actions, EnvironmentId=id
            )
            response.pop("ResponseMetadata", None)
            managed_actions[id] = response

            managed_action_history[id] = []
            response = try_except(
                EB_CLIENT.describe_environment_managed_action_history, EnvironmentId=id
            )
            response.pop("ResponseMetadata", None)
            managed_action_history[id] = response

            instances_health[id] = []
            response = try_except(EB_CLIENT.describe_instances_health, EnvironmentId=id)
            response.pop("ResponseMetadata", None)
            instances_health[id] = response

        response = try_except(EB_CLIENT.describe_applications)
        response.pop("ResponseMetadata", None)
        data = fix_json(response)
        applications = data

        response = try_except(EB_CLIENT.describe_account_attributes)
        response.pop("ResponseMetadata", None)
        data = response
        account_attributes = data

        results = []
        results.append(
            create_command(
                "aws elasticbeanstalk describe-environment-resources --environment-id <id>",
                resources,
            )
        )
        results.append(
            create_command(
                "aws elasticbeanstalk describe-environment-managed-actions --environment-id <id>",
                managed_actions,
            )
        )
        results.append(
            create_command(
                "aws elasticbeanstalk describe-environment-managed-action-history --environment-id <id>",
                managed_action_history,
            )
        )
        results.append(
            create_command(
                "aws elasticbeanstalk describe-instances-health --environment-id <id>",
                instances_health,
            )
        )
        results.append(
            create_command("aws elasticbeanstalk describe-environments", environments)
        )
        results.append(
            create_command("aws elasticbeanstalk describe-applications", applications)
        )
        results.append(
            create_command(
                "aws elasticbeanstalk describe-account-attributes", account_attributes
            )
        )

        self.results["eb"] = results
        self.display_progress(len(results), "elasticbeanstalk")
        return

    def get_configuration_route53(self):
        route53_list = self.services["route53"]

        if route53_list["count"] == -1:
            response = try_except(ROUTE53_CLIENT.list_hosted_zones)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            hosted_zones = response.get("HostedZones", [])

            identifiers = []
            for zone in hosted_zones:
                identifiers.append(zone["Id"])

            if len(identifiers) == 0:
                self.display_progress(0, "route53")
                return

        elif route53_list["count"] == 0:
            self.display_progress(0, "route53")
            return
        else:
            identifiers = route53_list["identifiers"]

        response = try_except(ROUTE53_CLIENT.list_traffic_policies)
        response.pop("ResponseMetadata", None)
        get_traffic_policies = response

        response = try_except(ROUTE53_RESOLVER_CLIENT.list_resolver_configs)
        response.pop("ResponseMetadata", None)
        resolver_configs = response

        response = try_except(ROUTE53_RESOLVER_CLIENT.list_firewall_configs)
        response.pop("ResponseMetadata", None)
        resolver_firewall_config = response

        response = try_except(ROUTE53_RESOLVER_CLIENT.list_resolver_query_log_configs)
        response.pop("ResponseMetadata", None)
        resolver_log_configs = response

        get_zones = []
        results = []

        for id in identifiers:
            response = try_except(ROUTE53_CLIENT.get_hosted_zone, Id=id)
            response.pop("ResponseMetadata", None)
            get_zones.append(response)

        results.append(
            create_command("aws route53 list-traffic-policies", get_traffic_policies)
        )
        results.append(
            create_command("aws route53 get-hosted-zone --id <string>", get_zones)
        )
        results.append(
            create_command(
                "aws route53resolver list-resolver-configs", resolver_configs
            )
        )
        results.append(
            create_command(
                "aws route53resolver list-resolver-query-log-configs",
                resolver_log_configs,
            )
        )
        results.append(
            create_command(
                "aws route53resolver list-firewall-configs ", resolver_firewall_config
            )
        )

        self.results["route53"] = results
        self.display_progress(len(results), "route53")
        return

    def get_configuration_ec2(self):
        ec2_list = self.services["ec2"]

        if ec2_list["count"] == -1:
            response = try_except(EC2_CLIENT.describe_instances)
            response.pop("ResponseMetadata", None)
            elements = fix_json(response)

            if elements["Reservations"]:
                elements = elements["Reservations"][0]["Instances"]

                if len(elements) == 0:
                    self.display_progress(0, "ec2")
                    return

            else:
                self.display_progress(0, "ec2")
                return

        elif ec2_list["count"] == 0:
            self.display_progress(0, "ec2")
            return

        response = try_except(EC2_CLIENT.describe_export_tasks)
        response.pop("ResponseMetadata", None)
        export = fix_json(response)

        response = try_except(EC2_CLIENT.describe_fleets)
        response.pop("ResponseMetadata", None)
        fleets = fix_json(response)

        response = try_except(EC2_CLIENT.describe_hosts)
        response.pop("ResponseMetadata", None)
        hosts = fix_json(response)

        response = try_except(EC2_CLIENT.describe_key_pairs)
        response.pop("ResponseMetadata", None)
        key_pairs = fix_json(response)

        response = try_except(EC2_CLIENT.describe_volumes)
        response.pop("ResponseMetadata", None)
        volumes = fix_json(response)

        response = try_except(EC2_CLIENT.describe_subnets)
        response.pop("ResponseMetadata", None)
        subnets = fix_json(response)

        response = try_except(EC2_CLIENT.describe_security_groups)
        response.pop("ResponseMetadata", None)
        sec_groups = fix_json(response)

        response = try_except(EC2_CLIENT.describe_route_tables)
        response.pop("ResponseMetadata", None)
        route_tables = fix_json(response)

        response = try_except(EC2_CLIENT.describe_snapshots)
        response.pop("ResponseMetadata", None)
        snapshots = fix_json(response)

        results = []
        results.append(create_command("aws ec2 describe-export-tasks", export))
        results.append(create_command("aws ec2 describe-fleets", fleets))
        results.append(create_command("aws ec2 describe-hosts", hosts))
        results.append(create_command("aws ec2 describe-key-pairs", key_pairs))
        results.append(create_command("aws ec2 describe-volumes", volumes))
        results.append(create_command("aws ec2 describe-subnets", subnets))
        results.append(create_command("aws ec2 describe-security-groups", sec_groups))
        results.append(create_command("aws ec2 describe-route-tables", route_tables))
        results.append(create_command("aws ec2 describe-snapshots", snapshots))

        self.results["ec2"] = results
        self.display_progress(len(results), "ec2")
        return

    def get_configuration_iam(self):
        iam_list = self.services["iam"]

        if iam_list["count"] == -1:
            response = try_except(IAM_CLIENT.list_users)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            elements = response.get("Users", [])

            if len(elements) == 0:
                self.display_progress(0, "ec2")
                return

        elif iam_list["count"] == 0:
            self.display_progress(0, "iam")
            return

        response = try_except(IAM_CLIENT.get_account_summary)
        response.pop("ResponseMetadata", None)
        get_summary = fix_json(response)

        response = try_except(IAM_CLIENT.get_account_authorization_details)
        response.pop("ResponseMetadata", None)
        get_auth_details = fix_json(response)

        response = try_except(IAM_CLIENT.list_ssh_public_keys)
        response.pop("ResponseMetadata", None)
        list_ssh_pub_keys = fix_json(response)

        response = try_except(IAM_CLIENT.list_mfa_devices)
        response.pop("ResponseMetadata", None)
        list_mfa_devices = fix_json(response)

        results = []
        results.append(create_command("aws iam get-account-summary", get_summary))
        results.append(
            create_command(
                "aws iam get-account-authorization-details", get_auth_details
            )
        )
        results.append(
            create_command("aws iam list-ssh-public-keys  ", list_ssh_pub_keys)
        )
        results.append(create_command("aws iam list-mfa-devices ", list_mfa_devices))

        self.results["iam"] = results
        self.display_progress(len(results), "iam")
        return

    def get_configuration_dynamodb(self):
        dynamodb_list = self.services["s3"]

        if dynamodb_list["count"] == -1:
            response = try_except(DYNAMODB_CLIENT.list_tables)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            tables = response.get("TableNames", [])

            if len(tables) == 0:
                self.display_progress(0, "dynamodb")
                return

        elif dynamodb_list["count"] == 0:
            self.display_progress(0, "dynamodb")
            return
        else:
            tables = dynamodb_list["elements"]

        tables_info = []
        export_info = []

        backups = try_except(DYNAMODB_CLIENT.list_backups)
        backups.pop("ResponseMetadata", None)

        response = try_except(DYNAMODB_CLIENT.list_exports)
        response.pop("ResponseMetadata", None)
        list_exports = response.get("ExportSummaries", [])

        for table in tables:
            response = try_except(DYNAMODB_CLIENT.describe_table, TableName=table)
            response.pop("ResponseMetadata", None)
            get_table = fix_json(response)
            tables_info.append(get_table)

        for export in list_exports:
            response = try_except(
                DYNAMODB_CLIENT.describe_export, ExportArn=export.get("ExportArn", "")
            )
            response.pop("ResponseMetadata", None)
            get_export = fix_json(response)
            export_info.append(get_export)

        results = []
        results.append(create_command("aws dynamodb list-backups", backups))
        results.append(
            create_command(
                "aws dynamodb describe-table --table-name <name>", tables_info
            )
        )
        results.append(create_command("aws dynamodb list-exports", list_exports))
        results.append(
            create_command(
                "aws dynamodb describe-export --export-arn <arn>", export_info
            )
        )

        self.results["dynamodb"] = results
        self.display_progress(len(results), "dynamodb")
        return

    def get_configuration_rds(self):
        rds_list = self.services["rds"]

        if rds_list["count"] == -1:
            response = try_except(RDS_CLIENT.describe_db_instances)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            elements = response.get("DBInstances", [])

            if len(elements) == 0:
                self.display_progress(0, "rds")
                return

        elif rds_list["count"] == 0:
            self.display_progress(0, "rds")
            return

        response = try_except(RDS_CLIENT.describe_db_clusters)
        response.pop("ResponseMetadata", None)
        clusters = fix_json(response)

        response = try_except(RDS_CLIENT.describe_db_snapshots)
        response.pop("ResponseMetadata", None)
        snapshots = fix_json(response)

        response = try_except(RDS_CLIENT.describe_db_proxies)
        response.pop("ResponseMetadata", None)
        proxies = fix_json(response)

        results = []
        results.append(create_command("aws rds describe-db-clusters", clusters))
        results.append(create_command("aws rds describe-db-snapshots", snapshots))
        results.append(create_command("aws rds describe-db-proxies ", proxies))

        self.results["rds"] = results
        self.display_progress(len(results), "rds")
        return

    def get_configuration_eks(self):
        eks_list = self.services["eks"]

        if eks_list["count"] == 0:
            # if there is not bucket at all
            self.display_progress(0, "eks")
            return

    def get_configuration_guardduty(self):
        guardduty_list = self.services["guardduty"]

        if guardduty_list["count"] == -1:
            response = try_except(GUARDDUTY_CLIENT.list_detectors)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            detectors = response.get("DetectorIds", [])

            if len(detectors) == 0:
                self.display_progress(0, "guardduty")
                return

        elif guardduty_list["count"] == 0:
            self.display_progress(0, "guardduty")
            return
        else:
            detectors = guardduty_list["ids"]

        detectors = {}
        filters = {}
        filter_data = {}
        publishing_destinations = {}
        threat_intel = {}
        ip_sets = {}

        for detector in detectors:
            response = try_except(GUARDDUTY_CLIENT.get_detector, DetectorId=detector)
            response.pop("ResponseMetadata", None)
            detectors[detector] = response

            response = try_except(GUARDDUTY_CLIENT.list_filters, DetectorId=detector)
            response.pop("ResponseMetadata", None)
            filters[detector] = response
            filter_names = response["FilterNames"]

            for filter_name in filter_names:
                filter_data[detector] = []
                response = try_except(
                    GUARDDUTY_CLIENT.get_filter,
                    DetectorId=detector,
                    FilterName=filter_name,
                )
                response.pop("ResponseMetadata", None)
                filter_data[detector].extend(response)

            response = try_except(
                GUARDDUTY_CLIENT.list_publishing_destinations, DetectorId=detector
            )
            response.pop("ResponseMetadata", None)
            publishing_destinations[detector] = response

            response = try_except(
                GUARDDUTY_CLIENT.list_threat_intel_sets, DetectorId=detector
            )
            response.pop("ResponseMetadata", None)
            threat_intel[detector] = response

            response = try_except(GUARDDUTY_CLIENT.list_ip_sets, DetectorId=detector)
            response.pop("ResponseMetadata", None)
            ip_sets[detector] = response

        results = []
        results.append(
            create_command("guardduty get-detector --detector-id <id>", detectors)
        )
        results.append(
            create_command("guardduty list-filters --detector-id <id>", filters)
        )
        results.append(
            create_command(
                "guardduty get-filter --detector-id <id> --filter-name <filter>",
                filter_data,
            )
        )
        results.append(
            create_command(
                "guardduty list-publishing-destinations --detector-id <id>",
                publishing_destinations,
            )
        )
        results.append(
            create_command(
                "guardduty list-threat-intel-sets --detector-id <id>", threat_intel
            )
        )
        results.append(
            create_command("guardduty list-ip-sets --detector-id <id>", ip_sets)
        )

        self.results["guardduty"] = results
        self.display_progress(len(results), "guardduty")
        return

    def get_configuration_cloudwatch(self):
        cloudwatch_list = self.services["cloudwatch"]

        if cloudwatch_list["count"] == -1:
            response = try_except(CLOUDWATCH_CLIENT.list_dashboards)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            dashboards = response.get("DashboardEntries", [])

            if len(dashboards) == 0:
                self.display_progress(0, "cloudwatch")
                return

        elif cloudwatch_list["count"] == 0:
            self.display_progress(0, "cloudwatch")
            return
        else:
            dashboards = cloudwatch_list["elements"]

        dashboards_data = {}
        for dashboard in dashboards:
            dashboard_name = dashboard["DashboardName"]
            if dashboard_name == "":
                continue
            response = try_except(
                CLOUDWATCH_CLIENT.get_dashboard, DashboardName=dashboard_name
            )
            response.pop("ResponseMetadata", None)
            dashboards_data[dashboard_name] = response

        response = try_except(CLOUDWATCH_CLIENT.list_metrics)
        response.pop("ResponseMetadata", None)
        metrics = response

        results = []
        results.append(
            create_command(
                "aws cloudwatch get-dashboard --name <name>", dashboards_data
            )
        )
        results.append(
            create_command("aws cloudwatch list-metrics --name <name>", metrics)
        )

        self.results["cloudwatch"] = results
        self.display_progress(len(results), "cloudwatch")
        return

    def get_configuration_maciev2(self):
        macie_list = self.services["macie"]

        if macie_list["count"] == -1:
            response = try_except(MACIE_CLIENT.describe_buckets)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            elements = response.get("buckets", [])

            if len(elements) == 0:
                self.display_progress(0, "macie")
                return
        elif macie_list["count"] == 0:
            self.display_progress(0, "macie")
            return

        response = try_except(MACIE_CLIENT.get_finding_statistics, groupBy="type")
        response.pop("ResponseMetadata", None)
        statistics_severity = fix_json(response)

        response = try_except(
            MACIE_CLIENT.get_finding_statistics, groupBy="severity.description"
        )
        response.pop("ResponseMetadata", None)
        statistics_type = fix_json(response)

        results = []
        results.append(
            create_command(
                "aws macie2 get-finding-statistics --group-by severity.description",
                statistics_severity,
            )
        )
        results.append(
            create_command(
                "aws macie2 get-finding-statistics --group-by type", statistics_type
            )
        )

        self.results["macie"] = results
        self.display_progress(len(results), "macie")
        return

    def get_configuration_inspector2(self):
        inspector_list = self.services["inspector"]

        response = try_except(INSPECTOR_CLIENT.list_coverage)
        response.pop("ResponseMetadata", None)
        coverage = fix_json(response)

        if inspector_list["count"] == -1:
            covered = coverage.get("coveredResources", [])

            if len(covered) == 0:
                self.display_progress(0, "inspector")
                return

        elif inspector_list["count"] == 0:
            self.display_progress(0, "inspector")
            return

        response = try_except(INSPECTOR_CLIENT.list_usage_totals)
        response.pop("ResponseMetadata", None)
        usage = fix_json(response)

        response = try_except(INSPECTOR_CLIENT.list_account_permissions)
        response.pop("ResponseMetadata", None)
        permission = fix_json(response)

        results = []
        results.append(create_command("aws inspector2 list-coverage", coverage))
        results.append(create_command("aws inspector2 list-usage-totals", usage))
        results.append(
            create_command("aws inspector2 list-account-permissions", permission)
        )

        self.results["inspector"] = results
        self.display_progress(len(results), "inspector")

    def get_configuration_detective(self):
        detective_list = self.services["detective"]

        response = try_except(DETECTIVE_CLIENT.list_graphs)
        response.pop("ResponseMetadata", None)
        graphs = fix_json(response)

        if detective_list["count"] == -1:
            glist = graphs.get("GraphList", [])

            if len(glist) == 0:
                self.display_progress(0, "inspector")
                return

        elif detective_list["count"] == 0:
            self.display_progress(0, "detective")
            return

        results = []
        results.append(create_command("aws detective list-graphs ", graphs))

        self.results["detective"] = results
        self.display_progress(len(results), "detective")

    def get_configuration_cloudtrail(self):
        cloudtrail_list = self.services["cloudtrail"]

        if cloudtrail_list["count"] == -1:
            response = try_except(CLOUDTRAIL_CLIENT.list_trails)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            trails = response.get("Trails", [])

            if len(trails) == 0:
                self.display_progress(0, "cloudtrail")
                return

        elif cloudtrail_list["count"] == 0:
            self.display_progress(0, "cloudtrail")
            return
        else:
            trails = cloudtrail_list["elements"]

        trails_data = {}
        for trail in trails:
            trail_name = trail.get("Name", "")
            if trail_name == "":
                continue
            response = try_except(CLOUDTRAIL_CLIENT.get_trail, Name=trail_name)
            response.pop("ResponseMetadata", None)
            trails_data[trail_name] = fix_json(response)

        results = []
        results.append(create_command("aws cloudtrail list-trails", trails))
        results.append(
            create_command("aws cloudtrail get-trail --name <name>", trails_data)
        )

        self.results["cloudtrail"] = results
        self.display_progress(len(results), "cloudtrail")

    def display_progress(self, count, name):
        if count != 0:
            print(
                "         \u2705 "
                + name.upper()
                + "\033[1m"
                + " - JSON File Extracted "
                + "\033[0m"
            )
        else:
            print(
                "         \u274c "
                + name.upper()
                + "\033[1m"
                + " - No Configuration"
                + "\033[0m"
            )
