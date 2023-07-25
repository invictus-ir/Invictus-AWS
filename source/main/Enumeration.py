from source.utils import *
from source.enum import *


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
            print("r")
            self.enumerate_s3()
            #self.enumerate_iam()   
            #self.enumerate_cloudtrail_trails()

        #self.enumerate_wafv2()
        #self.enumerate_lambda()m
        #self.enumerate_vpc()
        #self.enumerate_elasticbeanstalk()
#
        #self.enumerate_route53()
        #self.enumerate_ec2()
        #self.enumerate_dynamodb()
        #self.enumerate_rds()
        #self.enumerate_eks()
        #self.enumerate_elasticsearch()
        #self.enumerate_secrets()
        #self.enumerate_kinesis()
#
        #self.enumerate_cloudwatch()
        #self.enumerate_guardduty()
        #self.enumerate_detective()
        #self.enumerate_inspector2()
        #self.enumerate_maciev2()

        if self.dl:
            confs = ROOT_FOLDER + self.region + "/enumeration/"
            create_folder(confs)
            for el in self.services:
                if self.services[el]["count"] > 0:
                    write_file(
                        confs + f"{el}.json",
                        "w",
                        json.dumps(self.services[el], indent=4, default=str),
                    )
            print(f"\n[+] Enumeration results stored in the folder {ROOT_FOLDER}{self.region}/enumeration/\n")
        else:
            for key, value in self.services.items():
                if value["count"] > 0:
                    write_s3(
                        self.bucket,
                        f"{self.region}/enumeration/{key}.json",
                        json.dumps(value, indent=4, default=str),
                    )
            print(f"\n[+] Enumeration results stored in the bucket {self.bucket}\n")
        return self.services

    def enumerate_s3(self):
        
        elements  = s3_lookup()

        self.services["s3"]["count"] = len(elements)
        self.services["s3"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Name"])

        self.services["s3"]["ids"] = identifiers

        self.display_progress(self.services["s3"]["ids"], "s3")

    def enumerate_wafv2(self):

        elements = misc_lookup(WAF_CLIENT.list_web_acls, "NextMarker", "WebACLs", Scope="REGIONAL", Limit=100)

        self.services["wafv2"]["count"] = len(elements)
        self.services["wafv2"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["ARN"])

        self.services["wafv2"]["ids"] = identifiers

        self.display_progress(self.services["wafv2"]["ids"], "wafv2")
   
    def enumerate_lambda(self):

        elements = paginate(LAMBDA_CLIENT, "list_functions", "Functions")

        self.services["lambda"]["count"] = len(elements)
        self.services["lambda"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["FunctionName"])

        self.services["lambda"]["ids"] = identifiers

        self.display_progress(self.services["lambda"]["ids"], "lambda")

    def enumerate_vpc(self):

        elements = paginate(EC2_CLIENT, "describe_vpcs", "Vpcs")

        self.services["vpc"]["count"] = len(elements)
        self.services["vpc"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["VpcId"])

        self.services["vpc"]["ids"] = identifiers

        self.display_progress(self.services["vpc"]["ids"], "vpc")

    def enumerate_elasticbeanstalk(self):

        elements = paginate(EB_CLIENT, "describe_environments", "Environments")

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

        elements = paginate(ROUTE53_CLIENT, "list_hosted_zones", "HostedZones")

        self.services["route53"]["count"] = len(elements)
        self.services["route53"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Id"])

        self.services["route53"]["ids"] = identifiers

        self.display_progress(self.services["route53"]["ids"], "route53")

    def enumerate_ec2(self):

        elements = ec2_lookup()
        
        self.services["ec2"]["count"] = len(elements)
        self.services["ec2"]["elements"] = elements

        
        identifiers = []
        for el in elements:
            identifiers.append(el["InstanceId"])

        self.services["ec2"]["ids"] = identifiers
     
        self.display_progress(self.services["ec2"]["ids"], "ec2")

    def enumerate_iam(self):

        elements = paginate(IAM_CLIENT, "list_users", "Users")

        self.services["iam"]["count"] = len(elements)
        self.services["iam"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Arn"])

        self.services["iam"]["ids"] = identifiers

        self.display_progress(self.services["iam"]["ids"], "iam")

    def enumerate_dynamodb(self):

        elements = paginate(DYNAMODB_CLIENT, "list_tables", "TableNames")

        self.services["dynamodb"]["count"] = len(elements)
        self.services["dynamodb"]["elements"] = elements

        identifiers = elements

        self.services["dynamodb"]["ids"] = identifiers

        self.display_progress(self.services["dynamodb"]["ids"], "dynamodb")

    def enumerate_rds(self):

        elements = paginate(RDS_CLIENT, "describe_db_instances", "DBInstances")

        self.services["rds"]["count"] = len(elements)
        self.services["rds"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["DBInstanceArn"])

        self.services["rds"]["ids"] = identifiers

        self.display_progress(self.services["rds"]["ids"], "rds")

    def enumerate_eks(self):

        elements = paginate(EKS_CLIENT, "list_clusters", "clusters")

        self.services["eks"]["count"] = len(elements)
        self.services["eks"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el)

        self.services["eks"]["ids"] = identifiers

        self.display_progress(self.services["eks"]["ids"], "eks")

    def enumerate_elasticsearch(self):

        elements = elasticsearch_lookup()

        self.services["els"]["count"] = len(elements)
        self.services["els"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["DomainName"])

        self.services["els"]["ids"] = identifiers

        self.display_progress(self.services["els"]["ids"], "els")

    def enumerate_secrets(self):

        elements = paginate(SECRETS_CLIENT, "list_secrets", "SecretList")
            
        self.services["secrets"]["count"] = len(elements)
        self.services["secrets"]["elements"] = elements
                
        identifiers = []
        for el in elements:
            identifiers.append(el["ARN"])

        self.services["secrets"]["ids"] = identifiers

        self.display_progress(self.services["secrets"]["ids"], "secrets")

    def enumerate_kinesis(self):

        elements = paginate(KINESIS_CLIENT, "list_streams", "StreamNames")
                    
        self.services["kinesis"]["count"] = len(elements)
        self.services["kinesis"]["elements"] = elements

        self.services["kinesis"]["ids"] = elements

        self.display_progress(self.services["kinesis"]["ids"], "kinesis")

    def enumerate_cloudwatch(self):

        elements = paginate(CLOUDWATCH_CLIENT, "list_dashboards", "DashboardEntries")

        self.services["cloudwatch"]["count"] = len(elements)
        self.services["cloudwatch"]["elements"] = elements
       
        identifiers = []
        for el in elements:
            identifiers.append(el["DashboardArn"])

        self.services["cloudwatch"]["ids"] = identifiers

        self.display_progress(self.services["cloudwatch"]["ids"], "cloudwatch")

    def enumerate_cloudtrail_trails(self):

        elements = paginate(CLOUDTRAIL_CLIENT, "list_trails", "Trails")

        self.services["cloudtrail"]["count"] = len(elements)
        self.services["cloudtrail"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Name"])

        self.services["cloudtrail"]["ids"] = identifiers

        self.display_progress(self.services["cloudtrail"]["ids"], "cloudtrail")

    def enumerate_guardduty(self):

        elements = paginate(GUARDDUTY_CLIENT, "list_detectors", "DetectorIds")

        self.services["guardduty"]["count"] = len(elements)
        self.services["guardduty"]["elements"] = elements

        identifiers = elements

        self.services["guardduty"]["ids"] = identifiers

        self.display_progress(self.services["guardduty"]["ids"], "guardduty")

    def enumerate_inspector2(self):

        elements = paginate(INSPECTOR_CLIENT, "list_coverage", "coveredResources")
 
        self.services["inspector"]["count"] = len(elements)
        self.services["inspector"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["resourceId"])

        self.services["inspector"]["ids"] = identifiers

        self.display_progress(self.services["inspector"]["ids"], "inspector")

    def enumerate_detective(self):
        
        elements = misc_lookup(DETECTIVE_CLIENT.list_graphs, "NextToken", "GraphList", MaxResults=100)
    
        self.services["detective"]["count"] = len(elements)
        self.services["detective"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Arn"])

        self.services["detective"]["ids"] = identifiers

        self.display_progress(self.services["detective"]["ids"], "detective")

    def enumerate_maciev2(self):

        elements = paginate(MACIE_CLIENT, "describe_buckets", "buckets")

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
