"""File used for the enumeration."""

from source.utils.enum import *
from source.utils.utils import create_s3_if_not_exists, PREPARATION_BUCKET, ROOT_FOLDER, create_folder, set_clients, write_file, write_s3
import source.utils.utils
import json
from time import sleep


class Enumeration:

    services = {}
    bucket = ""
    region = None
    dl = None

    def __init__(self, region, dl):
        """Handle the constructor of the Enumeration class.
        
        Parameters
        ----------
        region : str
            Region in which to tool is executed
        dl : bool
            True if the user wants to download the results, False if he wants the results to be written in a s3 bucket
        """
        self.dl = dl
        self.region = region

        if not self.dl:
            self.bucket = create_s3_if_not_exists(self.region, PREPARATION_BUCKET)

    def self_test(self):
        """Test function."""
        print("[+] Enumeration test passed")

    def execute(self, services, regionless):
        """Handle the main function of the class. Run every enumeration function and then write the results where asked.
        
        Parameters
        ---------
        services : list
            Array used to write the results of the different enumerations functions
        regionless : str
            "not-all" if the tool is used on only one region. First region to run the tool on otherwise

        Returns
        -------
        self.services : object
            Object where the results of the functions are written
        """
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
            with tqdm(desc="[+] Writing results", leave=False, total = len(self.services)) as pbar:
                for el in self.services:
                    if self.services[el]["count"] > 0:
                        write_file(
                            confs + f"{el}.json",
                            "w",
                            json.dumps(self.services[el]["elements"], indent=4, default=str),
                        )
                    pbar.update() 
                    sleep(0.1)
            print(f"[+] Enumeration results stored in the folder {ROOT_FOLDER}{self.region}/enumeration/")
        else:
            with tqdm(desc="[+] Writing results", leave=False, total = len(self.services)) as pbar:
                for key, value in self.services.items():
                    if value["count"] > 0:
                        write_s3(
                            self.bucket,
                            f"{self.region}/enumeration/{key}.json",
                            json.dumps(value["elements"], indent=4, default=str)
                        )
                    pbar.update() 
                    sleep(0.1)
            print(f"[+] Enumeration results stored in the bucket {self.bucket}")

        return self.services

    def enumerate_s3(self):
        """Enumerate the s3 buckets available."""
        elements  = s3_lookup()

        self.services["s3"]["count"] = len(elements)
        self.services["s3"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Name"])

        self.services["s3"]["ids"] = identifiers

        self.display_progress(self.services["s3"]["ids"], "s3", True)
   
    def enumerate_wafv2(self):
        """Enumerate the waf web acls available."""
        elements = misc_lookup("WAF", source.utils.utils.WAF_CLIENT.list_web_acls, "NextMarker", "WebACLs", Scope="REGIONAL", Limit=100)

        self.services["wafv2"]["count"] = len(elements)
        self.services["wafv2"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["ARN"])

        self.services["wafv2"]["ids"] = identifiers

        self.display_progress(self.services["wafv2"]["ids"], "wafv2", True)
    
    def enumerate_lambda(self):
        """Enumerate the lambdas available."""
        elements = paginate(source.utils.utils.LAMBDA_CLIENT, "list_functions", "Functions")

        self.services["lambda"]["count"] = len(elements)
        self.services["lambda"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["FunctionName"])

        self.services["lambda"]["ids"] = identifiers

        self.display_progress(self.services["lambda"]["ids"], "lambda", True)
    
    def enumerate_vpc(self):
        """Enumerate the vpcs available."""
        elements = paginate(source.utils.utils.EC2_CLIENT, "describe_vpcs", "Vpcs")

        self.services["vpc"]["count"] = len(elements)
        self.services["vpc"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["VpcId"])

        self.services["vpc"]["ids"] = identifiers

        self.display_progress(self.services["vpc"]["ids"], "vpc", True)

    def enumerate_elasticbeanstalk(self):
        """Enumerate the elasticbeanstalk environments available."""
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
   
    def enumerate_route53(self):
        """Enumerate the routes53 hosted zones available."""
        elements = paginate(source.utils.utils.ROUTE53_CLIENT, "list_hosted_zones", "HostedZones")

        self.services["route53"]["count"] = len(elements)
        self.services["route53"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Id"])

        self.services["route53"]["ids"] = identifiers

        self.display_progress(self.services["route53"]["ids"], "route53", True)
  
    def enumerate_ec2(self):
        """Enumerate the ec2 instances available."""
        elements = ec2_lookup()
        
        self.services["ec2"]["count"] = len(elements)
        self.services["ec2"]["elements"] = elements

        
        identifiers = []
        for el in elements:
            identifiers.append(el["InstanceId"])

        self.services["ec2"]["ids"] = identifiers
     
        self.display_progress(self.services["ec2"]["ids"], "ec2", True)
   
    def enumerate_iam(self):
        """Enumerate the IAM users available."""
        elements = paginate(source.utils.utils.IAM_CLIENT, "list_users", "Users")

        self.services["iam"]["count"] = len(elements)
        self.services["iam"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Arn"])

        self.services["iam"]["ids"] = identifiers

        self.display_progress(self.services["iam"]["ids"], "iam", True)
    
    def enumerate_dynamodb(self):
        """Enumerate the dynamodb tables available."""
        elements = paginate(source.utils.utils.DYNAMODB_CLIENT, "list_tables", "TableNames")

        self.services["dynamodb"]["count"] = len(elements)
        self.services["dynamodb"]["elements"] = elements

        identifiers = elements

        self.services["dynamodb"]["ids"] = identifiers

        self.display_progress(self.services["dynamodb"]["ids"], "dynamodb", True)
  
    def enumerate_rds(self):
        """Enumerate the rds instances available."""
        elements = paginate(source.utils.utils.RDS_CLIENT, "describe_db_instances", "DBInstances")

        self.services["rds"]["count"] = len(elements)
        self.services["rds"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["DBInstanceArn"])

        self.services["rds"]["ids"] = identifiers

        self.display_progress(self.services["rds"]["ids"], "rds", True)
    
    def enumerate_eks(self):
        """Enumerate the eks clusters available."""
        elements = paginate(source.utils.utils.EKS_CLIENT, "list_clusters", "clusters")

        self.services["eks"]["count"] = len(elements)
        self.services["eks"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el)

        self.services["eks"]["ids"] = identifiers

        self.display_progress(self.services["eks"]["ids"], "eks", True)
    
    def enumerate_elasticsearch(self):
        """Enumerate the elasticsearch domains available."""
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
    
    def enumerate_secrets(self):
        """Enumerate the secretsmanager secrets available."""
        elements = paginate(source.utils.utils.SECRETS_CLIENT, "list_secrets", "SecretList")
            
        self.services["secrets"]["count"] = len(elements)
        self.services["secrets"]["elements"] = elements
                
        identifiers = []
        for el in elements:
            identifiers.append(el["ARN"])

        self.services["secrets"]["ids"] = identifiers

        self.display_progress(self.services["secrets"]["ids"], "secrets", True)
    
    def enumerate_kinesis(self):
        """Enumerate the kinesis streams available."""
        elements = paginate(source.utils.utils.KINESIS_CLIENT, "list_streams", "StreamNames")
                    
        self.services["kinesis"]["count"] = len(elements)
        self.services["kinesis"]["elements"] = elements

        self.services["kinesis"]["ids"] = elements

        self.display_progress(self.services["kinesis"]["ids"], "kinesis", True)
   
    def enumerate_cloudwatch(self):
        """Enumerate the cloudwatch dashboards available."""
        elements = paginate(source.utils.utils.CLOUDWATCH_CLIENT, "list_dashboards", "DashboardEntries")

        self.services["cloudwatch"]["count"] = len(elements)
        self.services["cloudwatch"]["elements"] = elements
       
        identifiers = []
        for el in elements:
            identifiers.append(el["DashboardArn"])

        self.services["cloudwatch"]["ids"] = identifiers

        self.display_progress(self.services["cloudwatch"]["ids"], "cloudwatch", True)
   
    def enumerate_cloudtrail_trails(self):
        """Enumerate the cloudtrail trails available."""
        elements = paginate(source.utils.utils.CLOUDTRAIL_CLIENT, "list_trails", "Trails")

        self.services["cloudtrail"]["count"] = len(elements)
        self.services["cloudtrail"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Name"])

        self.services["cloudtrail"]["ids"] = identifiers

        self.display_progress(self.services["cloudtrail"]["ids"], "cloudtrail", True)
    
    def enumerate_guardduty(self):
        """Enumerate the guardduty detectors available."""
        elements = paginate(source.utils.utils.GUARDDUTY_CLIENT, "list_detectors", "DetectorIds")

        self.services["guardduty"]["count"] = len(elements)
        self.services["guardduty"]["elements"] = elements

        identifiers = elements

        self.services["guardduty"]["ids"] = identifiers

        self.display_progress(self.services["guardduty"]["ids"], "guardduty", True)
    
    def enumerate_inspector2(self):
        """Enumerate the inspector coverages available."""
        elements = paginate(source.utils.utils.INSPECTOR_CLIENT, "list_coverage", "coveredResources")
 
        self.services["inspector"]["count"] = len(elements)
        self.services["inspector"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["resourceId"])

        self.services["inspector"]["ids"] = identifiers

        self.display_progress(self.services["inspector"]["ids"], "inspector", False)
    
    def enumerate_detective(self):
        """Enumerate the detective graphs available."""
        elements = misc_lookup("DETECTIVE", source.utils.utils.DETECTIVE_CLIENT.list_graphs, "NextToken", "GraphList", MaxResults=100)
    
        self.services["detective"]["count"] = len(elements)
        self.services["detective"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["Arn"])

        self.services["detective"]["ids"] = identifiers

        self.display_progress(self.services["detective"]["ids"], "detective", True)
    
    def enumerate_maciev2(self):
        """Enumerate the macie buckets available."""
        elements = paginate(source.utils.utils.MACIE_CLIENT, "describe_buckets", "buckets")

        self.services["macie"]["count"] = len(elements)
        self.services["macie"]["elements"] = elements

        identifiers = []
        for el in elements:
            identifiers.append(el["bucketArn"])

        self.services["macie"]["ids"] = identifiers

        self.display_progress(self.services["macie"]["ids"], "macie", True)
 
    def display_progress(self, ids, name, no_list=False):
        """Display the progress and the content of the service.

        Parameters
        ----------
        ids : list of str
            Identifiers of the elements of the service
        name : str
            Name of the service
        no_list : bool
            True if we don't want the name of each identifiers to be printed out. False otherwise
        """
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
