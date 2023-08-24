from source.utils.enum import *
from source.utils import create_s3_if_not_exists, PREPARATION_BUCKET, ROOT_FOLDER, create_folder, set_clients, write_file, write_s3
import source.utils
import json


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

    '''
    Test function
    '''
    def self_test(self):
        print("[+] Enumeration test passed")

    '''
    Main function of the class. Run every enumeration function and then write the results where asked
    services : Array used to write the results of the different enumerations functions
    regionless : "not-all" if the tool is used on only one region. First region to run the tool on otherwise
    '''
    def execute(self, services, regionless):
        print(f"[+] Beginning Enumeration of Services")

        set_clients(self.region)

        self.services = services

        if (regionless != "" and regionless == self.region) or regionless == "not-all":
            self.enumerate_s3()
            self.enumerate_iam()   
            self.enumerate_cloudtrail_trails()
            self.enumerate_route53()

        self.enumerate_wafv2()
        self.enumerate_lambda()
        self.enumerate_vpc()
        self.enumerate_elasticbeanstalk()

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
                        confs + f"{el}.json",
                        "w",
                        json.dumps(self.services[el]["elements"], indent=4, default=str),
                    )
            print(f"[+] Enumeration results stored in the folder {ROOT_FOLDER}{self.region}/enumeration/")
        else:
            for key, value in self.services.items():
                if value["count"] > 0:
                    write_s3(
                        self.bucket,
                        f"{self.region}/enumeration/{key}.json",
                        json.dumps(value["elements"], indent=4, default=str),
                    )
            print(f"[+] Enumeration results stored in the bucket {self.bucket}")
        return self.services

    '''
    Enumerate the s3 buckets available
    '''
    def enumerate_s3(self):
        
        elements  = s3_lookup()

        self.services["s3"]["count"] = len(elements)
        self.services["s3"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Name"])

        self.services["s3"]["ids"] = identifiers

        self.display_progress(self.services["s3"]["ids"], "s3", True)
    
    '''
    Enumerate the waf web acls available
    '''
    def enumerate_wafv2(self):

        elements = misc_lookup(source.utils.utils.WAF_CLIENT.list_web_acls, "NextMarker", "WebACLs", Scope="REGIONAL", Limit=100)

        self.services["wafv2"]["count"] = len(elements)
        self.services["wafv2"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["ARN"])

        self.services["wafv2"]["ids"] = identifiers

        self.display_progress(self.services["wafv2"]["ids"], "wafv2", True)
    
    '''
    Enumerate the lambdas available
    '''   
    def enumerate_lambda(self):

        elements = paginate(source.utils.utils.LAMBDA_CLIENT, "list_functions", "Functions")

        self.services["lambda"]["count"] = len(elements)
        self.services["lambda"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["FunctionName"])

        self.services["lambda"]["ids"] = identifiers

        self.display_progress(self.services["lambda"]["ids"], "lambda", True)
    
    '''
    Enumerate the vpcs available
    '''
    def enumerate_vpc(self):

        elements = paginate(source.utils.utils.EC2_CLIENT, "describe_vpcs", "Vpcs")

        self.services["vpc"]["count"] = len(elements)
        self.services["vpc"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["VpcId"])

        self.services["vpc"]["ids"] = identifiers

        self.display_progress(self.services["vpc"]["ids"], "vpc", True)

    '''
    Enumerate the elasticbeanstalk environments available
    '''
    def enumerate_elasticbeanstalk(self):

        elements = paginate(source.utils.utils.EB_CLIENT, "describe_environments", "Environments")
        
        self.services["elasticbeanstalk"]["count"] = len(elements)
        self.services["elasticbeanstalk"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["EnvironmentArn"])

        self.services["elasticbeanstalk"]["ids"] = identifiers

        self.display_progress(
            self.services["elasticbeanstalk"]["ids"], "elasticbeanstalk", True
        )
    
    '''
    Enumerate the routes53 hosted zones available
    '''
    def enumerate_route53(self):

        elements = paginate(source.utils.utils.ROUTE53_CLIENT, "list_hosted_zones", "HostedZones")

        self.services["route53"]["count"] = len(elements)
        self.services["route53"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Id"])

        self.services["route53"]["ids"] = identifiers

        self.display_progress(self.services["route53"]["ids"], "route53", True)
    
    '''
    Enumerate the ec2 instances available
    '''
    def enumerate_ec2(self):

        elements = ec2_lookup()
        
        self.services["ec2"]["count"] = len(elements)
        self.services["ec2"]["elements"] = elements

        
        identifiers = []
        for el in elements:
            identifiers.append(el["InstanceId"])

        self.services["ec2"]["ids"] = identifiers
     
        self.display_progress(self.services["ec2"]["ids"], "ec2", True)
    
    '''
    Enumerate the IAM users available
    '''
    def enumerate_iam(self):

        elements = paginate(source.utils.utils.IAM_CLIENT, "list_users", "Users")

        self.services["iam"]["count"] = len(elements)
        self.services["iam"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Arn"])

        self.services["iam"]["ids"] = identifiers

        self.display_progress(self.services["iam"]["ids"], "iam", True)
    
    '''
    Enumerate the dynamodb tables available
    '''
    def enumerate_dynamodb(self):

        elements = paginate(source.utils.utils.DYNAMODB_CLIENT, "list_tables", "TableNames")

        self.services["dynamodb"]["count"] = len(elements)
        self.services["dynamodb"]["elements"] = elements

        identifiers = elements

        self.services["dynamodb"]["ids"] = identifiers

        self.display_progress(self.services["dynamodb"]["ids"], "dynamodb", True)
    
    '''
    Enumerate the rds instances available
    '''
    def enumerate_rds(self):

        elements = paginate(source.utils.utils.RDS_CLIENT, "describe_db_instances", "DBInstances")

        self.services["rds"]["count"] = len(elements)
        self.services["rds"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["DBInstanceArn"])

        self.services["rds"]["ids"] = identifiers

        self.display_progress(self.services["rds"]["ids"], "rds", True)
    
    '''
    Enumerate the eks clusters available
    '''
    def enumerate_eks(self):

        elements = paginate(source.utils.utils.EKS_CLIENT, "list_clusters", "clusters")

        self.services["eks"]["count"] = len(elements)
        self.services["eks"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el)

        self.services["eks"]["ids"] = identifiers

        self.display_progress(self.services["eks"]["ids"], "eks", True)
    
    '''
    Enumerate the elasticsearch domains available
    '''
    def enumerate_elasticsearch(self):

        response = try_except(source.utils.utils.ELS_CLIENT.list_domain_names)
        response.pop("ResponseMetadata", None)
        response = fix_json(response)
        elements = response.get("DomainNames", [])

        self.services["els"]["count"] = len(elements)
        self.services["els"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["DomainName"])

        self.services["els"]["ids"] = identifiers

        self.display_progress(self.services["els"]["ids"], "els", True)
    
    '''
    Enumerate the secretsmanager secrets available
    '''
    def enumerate_secrets(self):

        elements = paginate(source.utils.utils.SECRETS_CLIENT, "list_secrets", "SecretList")
            
        self.services["secrets"]["count"] = len(elements)
        self.services["secrets"]["elements"] = elements
                
        identifiers = []
        for el in elements:
            identifiers.append(el["ARN"])

        self.services["secrets"]["ids"] = identifiers

        self.display_progress(self.services["secrets"]["ids"], "secrets", True)
    
    '''
    Enumerate the kinesis streams available
    '''
    def enumerate_kinesis(self):

        elements = paginate(source.utils.utils.KINESIS_CLIENT, "list_streams", "StreamNames")
                    
        self.services["kinesis"]["count"] = len(elements)
        self.services["kinesis"]["elements"] = elements

        self.services["kinesis"]["ids"] = elements

        self.display_progress(self.services["kinesis"]["ids"], "kinesis", True)
    
    '''
    Enumerate the cloudwatch dashboards available
    '''
    def enumerate_cloudwatch(self):

        elements = paginate(source.utils.utils.CLOUDWATCH_CLIENT, "list_dashboards", "DashboardEntries")

        self.services["cloudwatch"]["count"] = len(elements)
        self.services["cloudwatch"]["elements"] = elements
       
        identifiers = []
        for el in elements:
            identifiers.append(el["DashboardArn"])

        self.services["cloudwatch"]["ids"] = identifiers

        self.display_progress(self.services["cloudwatch"]["ids"], "cloudwatch", True)
    
    '''
    Enumerate the cloudtrail trails available
    '''
    def enumerate_cloudtrail_trails(self):

        elements = paginate(source.utils.utils.CLOUDTRAIL_CLIENT, "list_trails", "Trails")

        self.services["cloudtrail"]["count"] = len(elements)
        self.services["cloudtrail"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Name"])

        self.services["cloudtrail"]["ids"] = identifiers

        self.display_progress(self.services["cloudtrail"]["ids"], "cloudtrail", True)
    
    '''
    Enumerate the guardduty detectors available
    '''
    def enumerate_guardduty(self):

        elements = paginate(source.utils.utils.GUARDDUTY_CLIENT, "list_detectors", "DetectorIds")

        self.services["guardduty"]["count"] = len(elements)
        self.services["guardduty"]["elements"] = elements

        identifiers = elements

        self.services["guardduty"]["ids"] = identifiers

        self.display_progress(self.services["guardduty"]["ids"], "guardduty", True)
    
    '''
    Enumerate the inspector coverages available
    '''
    def enumerate_inspector2(self):

        elements = paginate(source.utils.utils.INSPECTOR_CLIENT, "list_coverage", "coveredResources")
 
        self.services["inspector"]["count"] = len(elements)
        self.services["inspector"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["resourceId"])

        self.services["inspector"]["ids"] = identifiers

        self.display_progress(self.services["inspector"]["ids"], "inspector", False)
    
    '''
    Enumerate the detective graphs available
    '''
    def enumerate_detective(self):
        
        elements = misc_lookup(source.utils.utils.DETECTIVE_CLIENT.list_graphs, "NextToken", "GraphList", MaxResults=100)
    
        self.services["detective"]["count"] = len(elements)
        self.services["detective"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Arn"])

        self.services["detective"]["ids"] = identifiers

        self.display_progress(self.services["detective"]["ids"], "detective", True)
    
    '''
    Enumerate the macie buckets available
    '''
    def enumerate_maciev2(self):

        elements = paginate(source.utils.utils.MACIE_CLIENT, "describe_buckets", "buckets")

        self.services["macie"]["count"] = len(elements)
        self.services["macie"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["bucketArn"])

        self.services["macie"]["ids"] = identifiers

        self.display_progress(self.services["macie"]["ids"], "macie", True)
    
    '''
    Display the progress and the content of the service
    ids : Identifiers of the elements of the service
    name : name of the service
    no_list : True if we don't want the name of each identifiers to be printed out. False otherwise
    '''
    def display_progress(self, ids, name, no_list=False):
        if len(ids) != 0:
            if no_list:
                print("\t\u2705 " + name.upper() + "\033[1m" + " - Available")
            else:
                print(
                    "\t\u2705 "
                    + name.upper()
                    + "\033[1m"
                    + " - Available with a count of "
                    + str(len(ids))
                    + "\033[0m"
                    + " and with the following identifiers: "
                )
                for identity in ids:
                    print("\t\t\u2022 " + identity)
        else:
            print(
                "\t\u274c "
                + name.upper()
                + "\033[1m"
                + " - Not Available"
                + "\033[0m"
            )
