from source.utils import *


class Enumeration:
    services = {}
    bucket = ""
    region = None
    dl = None

    def __init__(self, region, dl):
        self.dl = dl
        self.region = region

        if not self.dl:
            self.bucket = create_s3_if_not_exists(self.region, PREPARATION_BUCKET)

    def self_test(self):
        print("[+] Enumeration test passed")

    def execute(self, services, regionless):
        print("\n=====================")
        print(f"[+] Enumeration Step")
        print("=====================\n")

        self.services = services

        if (regionless != "" and regionless == self.region) or regionless == "not-all":
            self.enumerate_s3()
            self.enumerate_iam()
            self.enumerate_cloudtrail_logs()
            self.enumerate_cloudtrail_trails()

        self.enumerate_wafv2()
        self.enumerate_lambda()
        self.enumerate_vpc()
        self.enumerate_elasticbeanstalk()

        self.enumerate_route53()
        self.enumerate_ec2()
        self.enumerate_dynamodb()
        self.enumerate_rds()
        self.enumerate_eks()
        self.enumerate_elasticsearch()
        self.enumerate_secrets()
        self.enumerate_kinesis()

        self.enumerate_cloudwatch()
        self.enumerate_guardduty()
        self.enumerate_detective()
        self.enumerate_inspector2()
        self.enumerate_maciev2()

        if self.dl:
            confs = ROOT_FOLDER + self.region + "/enumeration/"
            create_folder(confs)
            for el in self.services:
                if self.services[el]["count"] > 0:
                    write_file(
                        confs + f"{el}_enumeration.json",
                        "w",
                        json.dumps(self.services[el], indent=4, default=str),
                    )
        else:
            for el in self.services:
                if el["count"] > 0:
                    write_s3(
                        self.bucket,
                        f"{self.region}/enumeration/{el}_enumeration.json",
                        json.dumps(self.services[el], indent=4, default=str),
                    )
        return self.services

    def enumerate_s3(self):
        response = try_except(S3_CLIENT.list_buckets)
        response.pop("ResponseMetadata", None)
        buckets = fix_json(response)

        elements = []
        elements = buckets.get("Buckets", [])

        self.services["s3"]["count"] = len(elements)
        self.services["s3"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Name"])

        self.services["s3"]["ids"] = identifiers

        self.display_progress(self.services["s3"]["ids"], "s3")

    def enumerate_wafv2(self):
        response = try_except(WAF_CLIENT.list_web_acls, Scope="REGIONAL")
        response.pop("ResponseMetadata", None)
        elements = response.get("WebACLs", [])

        self.services["wafv2"]["count"] = len(elements)
        self.services["wafv2"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["ARN"])

        self.services["wafv2"]["ids"] = identifiers

        self.display_progress(self.services["wafv2"]["ids"], "wafv2")

    def enumerate_lambda(self):
        response = try_except(LAMBDA_CLIENT.list_functions)
        response.pop("ResponseMetadata", None)
        elements = response.get("Functions", [])

        self.services["lambda"]["count"] = len(elements)
        self.services["lambda"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["FunctionName"])

        self.services["lambda"]["ids"] = identifiers

        self.display_progress(self.services["lambda"]["ids"], "lambda")

    def enumerate_vpc(self):
        response = try_except(EC2_CLIENT.describe_vpcs)
        response.pop("ResponseMetadata", None)
        elements = response.get("Vpcs", [])

        self.services["vpc"]["count"] = len(elements)
        self.services["vpc"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["VpcId"])

        self.services["vpc"]["ids"] = identifiers

        self.display_progress(self.services["vpc"]["ids"], "vpc")

    def enumerate_elasticbeanstalk(self):
        response = try_except(EB_CLIENT.describe_environments)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("Environments", [])

        self.services["elasticbeanstalk"]["count"] = len(elements)
        self.services["elasticbeanstalk"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["EnvironmentArn"])

        self.services["elasticbeanstalk"]["ids"] = identifiers

        self.display_progress(
            self.services["elasticbeanstalk"]["ids"], "elasticbeanstalk"
        )

    def enumerate_route53(self):
        response = try_except(ROUTE53_CLIENT.list_hosted_zones)
        response.pop("ResponseMetadata", None)
        elements = response.get("HostedZones", [])

        self.services["route53"]["count"] = len(elements)
        self.services["route53"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Id"])

        self.services["route53"]["ids"] = identifiers

        self.display_progress(self.services["route53"]["ids"], "route53")

    def enumerate_ec2(self):
        response = try_except(EC2_CLIENT.describe_instances)
        response.pop("ResponseMetadata", None)
        elements = fix_json(response)

        if elements["Reservations"]:
            elements = elements["Reservations"][0]["Instances"]

            self.services["ec2"]["count"] = len(elements)
            self.services["ec2"]["elements"] = elements

            identifiers = []
            for el in elements:
                identifiers.append(el["InstanceId"])

            self.services["ec2"]["ids"] = identifiers

        else:
            self.services["ec2"]["count"] = 0

        self.display_progress(self.services["ec2"]["ids"], "ec2")

    def enumerate_iam(self):
        response = try_except(IAM_CLIENT.list_users)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("Users", [])

        self.services["iam"]["count"] = len(elements)
        self.services["iam"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Arn"])

        self.services["iam"]["ids"] = identifiers

        self.display_progress(self.services["iam"]["ids"], "iam")

    def enumerate_dynamodb(self):
        response = try_except(DYNAMODB_CLIENT.list_tables)
        response.pop("ResponseMetadata", None)
        elements = response.get("TableNames", [])

        self.services["dynamodb"]["count"] = len(elements)
        self.services["dynamodb"]["elements"] = elements

        identifiers = elements

        self.services["dynamodb"]["ids"] = identifiers

        self.display_progress(self.services["dynamodb"]["ids"], "dynamodb")

    def enumerate_rds(self):
        response = try_except(RDS_CLIENT.describe_db_instances)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("DBInstances", [])

        self.services["rds"]["count"] = len(elements)
        self.services["rds"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["DBInstanceArn"])

        self.services["rds"]["ids"] = identifiers

        self.display_progress(self.services["rds"]["ids"], "rds")

    def enumerate_eks(self):
        response = try_except(EKS_CLIENT.list_clusters)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("clusters", [])

        self.services["eks"]["count"] = len(elements)
        self.services["eks"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el)

        self.services["eks"]["ids"] = identifiers

        self.display_progress(self.services["eks"]["ids"], "eks")

    def enumerate_elasticsearch(self):
        response = try_except(ELS_CLIENT.list_domain_names)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("DomainNames", [])

        self.services["els"]["count"] = len(elements)
        self.services["els"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["DomainName"])

        self.services["els"]["ids"] = identifiers

        self.display_progress(self.services["els"]["ids"], "els")

    def enumerate_secrets(self):
        response = try_except(SECRETS_CLIENT.list_secrets)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("SecretList", [])

        self.services["secrets"]["count"] = len(elements)
        self.services["secrets"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["ARN"])

        self.services["secrets"]["ids"] = identifiers

        self.display_progress(self.services["secrets"]["ids"], "secrets")

    def enumerate_kinesis(self):
        response = try_except(KINESIS_CLIENT.list_streams)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("StreamNames", [])

        self.services["kinesis"]["count"] = len(elements)
        self.services["kinesis"]["elements"] = elements

        self.services["kinesis"]["ids"] = elements

        self.display_progress(self.services["kinesis"]["ids"], "kinesis")

    def enumerate_cloudwatch(self):
        response = try_except(CLOUDWATCH_CLIENT.list_dashboards)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("DashboardEntries", [])

        self.services["cloudwatch"]["count"] = len(elements)
        self.services["cloudwatch"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["DashboardArn"])

        self.services["cloudwatch"]["ids"] = identifiers

        self.display_progress(self.services["cloudwatch"]["ids"], "cloudwatch")

    def enumerate_cloudtrail_logs(self):
        response = try_except(CLOUDTRAIL_CLIENT.lookup_events)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("Events", [])

        self.services["cloudtrail-logs"]["count"] = len(elements)
        self.services["cloudtrail-logs"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["EventId"])

        self.services["cloudtrail-logs"]["ids"] = identifiers

        self.display_progress(
            self.services["cloudtrail-logs"]["ids"], "cloudtrail-logs"
        )

    def enumerate_cloudtrail_trails(self):
        response = try_except(CLOUDTRAIL_CLIENT.list_trails)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("Trails", [])

        self.services["cloudtrail"]["count"] = len(elements)
        self.services["cloudtrail"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Name"])

        self.services["cloudtrail"]["ids"] = identifiers

        self.display_progress(self.services["cloudtrail"]["ids"], "cloudtrail")

    def enumerate_guardduty(self):
        response = try_except(GUARDDUTY_CLIENT.list_detectors)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("DetectorIds", [])

        self.services["guardduty"]["count"] = len(elements)
        self.services["guardduty"]["elements"] = elements

        identifiers = elements

        self.services["guardduty"]["ids"] = identifiers

        self.display_progress(self.services["guardduty"]["ids"], "guardduty")

    def enumerate_inspector2(self):
        response = try_except(INSPECTOR_CLIENT.list_coverage)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("coveredResources", [])

        self.services["inspector"]["count"] = len(elements)
        self.services["inspector"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["resourceId"])

        self.services["inspector"]["ids"] = identifiers

        self.display_progress(self.services["inspector"]["ids"], "inspector")

    def enumerate_detective(self):
        response = try_except(DETECTIVE_CLIENT.list_graphs)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("GraphList", [])

        self.services["detective"]["count"] = len(elements)
        self.services["detective"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Arn"])

        self.services["detective"]["ids"] = identifiers

        self.display_progress(self.services["detective"]["ids"], "detective")

    def enumerate_maciev2(self):
        response = try_except(MACIE_CLIENT.describe_buckets)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("buckets", [])

        self.services["macie"]["count"] = len(elements)
        self.services["macie"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["bucketArn"])

        self.services["macie"]["ids"] = identifiers

        self.display_progress(self.services["macie"]["ids"], "macie")

    def display_progress(self, ids, name, no_list=False):
        if len(ids) != 0:
            if no_list:
                print("\t\t\u2705 " + name.upper() + "\033[1m" + " - Available")
            else:
                print(
                    "\t\t\u2705 "
                    + name.upper()
                    + "\033[1m"
                    + " - Available with a count of "
                    + str(len(ids))
                    + "\033[0m"
                    + " and with the following identifiers: "
                )
                for identity in ids:
                    print("\t\t\t\u2022 " + identity)
        else:
            print(
                "\t\t\u274c "
                + name.upper()
                + "\033[1m"
                + " - Not Available"
                + "\033[0m"
            )
