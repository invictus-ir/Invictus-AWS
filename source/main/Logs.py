import boto3, os, time, requests, json

import source.utils
from source.utils import write_file, create_folder, copy_or_write_s3, create_command, writefile_s3, ROLE_JSON, run_s3_dl, LOGS_RESULTS, create_s3_if_not_exists, LOGS_BUCKET, ROOT_FOLDER, set_clients
from source.enum import *


class Logs:
    bucket = None
    region = None
    dl = None
    confs = None
    results = None

    def __init__(self, region, dl):

        self.region = region
        self.results = LOGS_RESULTS

        if dl:
            self.dl = dl
            self.confs = ROOT_FOLDER + self.region + "/logs"
            create_folder(self.confs)
        else:
            self.bucket = create_s3_if_not_exists(self.region, LOGS_BUCKET)

    '''
    Test function
    '''
    def self_test(self):
        print("[+] Logs Extraction test passed\n")

    '''
    Main function of the class. Run every logs extraction function and then write the results where asked
    services : Array used to write the results of the different enumerations functions
    regionless : "not-all" if the tool is used on only one region. First region to run the tool on otherwise
    '''
    def execute(self, services, regionless):
        print("\n========================")
        print(f"[+] Logs Extraction Step")
        print("========================\n")

        set_clients(self.region)

        self.services = services
        if regionless == self.region or regionless == "not-all":
            self.get_logs_s3()
            self.get_logs_cloudtrail_logs()

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

        if self.dl:
            for key, value in self.results.items():
                if value["action"] == 0:
                    write_file(
                        self.confs + f"/{key}.json",
                        "w",
                        json.dumps(value["results"], indent=4, default=str),
                    )
                else:
                    for bucket in value["results"]:
                        path = f"{self.confs}/{key}"
                        create_folder(path) 
                        prefix = ""
                        
                        if "|" in bucket:
                            split = bucket.split("|")
                            bucket = split[0]
                            prefix = split[1]
                        run_s3_dl(bucket, path, prefix)

            print(f"\n[+] Logs extraction results stored in the folder {self.confs}\n")
        else:
            for key, value in self.results.items():
                if value["results"]:
                    copy_or_write_s3(key, value, self.bucket, self.region)

            print(f"\n[+] Logs extraction results stored in the bucket {self.bucket}\n")

    '''
    Retrieve the logs of the existing guardduty detectors
    '''
    def get_logs_guardduty(self):
        guardduty_list = self.services["guardduty"]

        '''
        In the first part, we verify that the enumeration of the service is already done. 
        If it doesn't, we redo it.
        If it is, we verify if the service is available or not.
        '''

        if guardduty_list["count"] == -1:
            detectors_ids = paginate(source.utils.GUARDDUTY_CLIENT, "list_detectors", "DetectorIds")

            if len(detectors_ids) == 0:
                self.display_progress(0, "guardduty")
                return

        elif guardduty_list["count"] == 0:
            self.display_progress(0, "guardduty")
            return
        else:
            detector_ids = guardduty_list["ids"]

        '''
        In this part, we get the logs of the service (if existing)
        Then all the results are added to a same json file.
        '''

        findings_data = {}
        for detector in detector_ids:
            findings = paginate(source.utils.GUARDDUTY_CLIENT, "list_findings", "FindingIds", DetectorId=detector)

            response = try_except(
                source.utils.GUARDDUTY_CLIENT.get_findings, DetectorId=detector, FindingIds=findings
            )
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            findings_data[detector] = response

        results = []
        results.append(
            create_command(
                "guardduty get-findings --detector-id <id> --findings-id <ids>",
                findings_data,
            )
        )

        self.results["guardduty"]["action"] = 0
        self.results["guardduty"]["results"] = results

        self.display_progress(len(results), "guardduty")

    '''
    Retrieve the cloudtrail logs
    '''
    def get_logs_cloudtrail_logs(self):

        logs = paginate(source.utils.CLOUDTRAIL_CLIENT, "lookup_events", "Events")

        if len(logs) == 0:
            self.display_progress(0, "cloudtrail")
            return
        
        self.results["cloudtrail-logs"]["action"] = 0
        self.results["cloudtrail-logs"]["results"] = logs
        
        self.display_progress(1, "cloudtrail-logs")

    '''
    Retrieve the logs of the existing waf web acls
    '''
    def get_logs_wafv2(self):
        waf_list = self.services["wafv2"]

        if waf_list["count"] == -1:
            wafs = misc_lookup(source.utils.WAF_CLIENT.list_web_acls, "NextMarker", "WebACLs", Scope="REGIONAL", Limit=100)

            if len(wafs) == 0:
                self.display_progress(0, "wafv2")
                return

            identifiers = []
            for el in wafs:
                identifiers.append(el["ARN"])

        elif waf_list["count"] == 0:
            self.display_progress(0, "wafv2")
            return
        else:
            identifiers = waf_list["ids"]
            return identifiers

        cnt = 0

        self.results["wafv2"]["action"] = 1

        for arn in identifiers:
            logging = try_except(source.utils.WAF_CLIENT.get_logging_configuration, ResourceArn=arn)
            if "LoggingConfiguration" in logging:
                destinations = logging["LoggingConfiguration"]["LogDestinationConfigs"]
                for destination in destinations:
                    if "s3" in destination:
                        bucket = destination.split(":")[-1]
                        src_bucket = bucket.split("/")[0]

                        self.results["wafv2"]["results"].append(src_bucket)

                        cnt += 1

        self.display_progress(cnt, "wafv2")

    '''
    Retrieve the logs of the existing vpcs
    '''
    def get_logs_vpc(self):
        vpc_list = self.services["vpc"]

        if vpc_list["count"] == -1:
            vpcs = paginate(source.utils.EC2_CLIENT, "describe_vpcs", "Vpcs")

            if len(vpcs) == 0:
                self.display_progress(0, "vpc")
                return

        elif vpc_list["count"] == 0:
            self.display_progress(0, "vpc")
            return

        flow_logs = paginate(source.utils.EC2_CLIENT, "describe_flow_logs", "FlowLogs")
        cnt = 0

        self.results["vpc"]["action"] = 1

        for flow_log in flow_logs:
            if "s3" in flow_log["LogDestinationType"]:
                bucket = flow_log["LogDestination"].split(":")[-1]
                src_bucket = bucket.split("/")[0]

                self.results["vpc"]["results"].append(src_bucket)
                cnt += 1
        self.display_progress(cnt, "vpc")
    
    '''
    Retrieve the logs of the configuration of the existing elasticbeanstalk environments
    '''    
    def get_logs_elasticbeanstalk(self):
        eb = boto3.client("elasticbeanstalk")

        eb_list = self.services["elasticbeanstalk"]

        if eb_list["count"] == -1:

            environments = paginate(source.utils.EB_CLIENT, "describe_environments", "Environments")

            if len(environments) == 0:
                self.display_progress(0, "elasticbeanstalk")
                return

        elif eb_list["count"] == 0:
            self.display_progress(0, "elasticbeanstalk")
            return
        else:
            environments = eb_list["elements"]

        path = self.confs + "elasticbeanstalk/"
        create_folder(path)

        for environment in environments:
            name = environment.get("EnvironmentName", "")
            if name == "":
                continue

            response = try_except(
                eb.request_environment_info, EnvironmentName=name, InfoType="bundle"
            )
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            time.sleep(60)

            response = try_except(
                eb.retrieve_environment_info, EnvironmentName=name, InfoType="bundle"
            )
            response.pop("ResponseMetadata", None)
            response = fix_json(response)

            urls = response["EnvironmentInfo"]
            if len(urls) > 0:
                url = urls[-1]
                url = url["Message"]

            filename = path + name + ".zip"
            r = requests.get(url)
            with open(filename, "wb") as f:
                f.write(r.content)

            if not self.dl:
                key = "eb/" + name + ".zip"
                writefile_s3(self.bucket, key, filename)
                os.remove(filename)
                os.rmdir(path)

        self.display_progress(len(environments), "elasticbeanstalk")
    
    '''
    Retrieve the logs of the configuration of the existing cloudwatch dashboards
    '''
    def get_logs_cloudwatch(self):
        cloudwatch_list = self.services["cloudwatch"]

        if cloudwatch_list["count"] == -1:
            dashboards = paginate(source.utils.CLOUDWATCH_CLIENT, "list_dashboards", "DashboardEntries")

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
            dashboard_name = dashboard.get("DashboardName", "")
            if dashboard_name == "":
                continue
            response = try_except(
                source.utils.CLOUDWATCH_CLIENT.get_dashboard, DashboardName=dashboard_name
            )
            response.pop("ResponseMetadata", None)
            dashboards_data[dashboard_name] = fix_json(response)

        metrics = try_except(source.utils.CLOUDWATCH_CLIENT, "list_metrics")

        alarms = simple_paginate(source.utils.CLOUDWATCH_CLIENT, "describe_alarms")

        results = []
        results.append(
            create_command("cloudwatch get-dashboard --name <name>", dashboards_data)
        )
        results.append(create_command("cloudwatch list-metrics --name <name>", metrics))
        results.append(
            create_command("cloudwatch describe-alarms --name <name>", alarms)
        )

        self.results["cloudwatch"]["action"] = 0
        self.results["cloudwatch"]["results"] = results

        self.display_progress(len(results), "cloudwatch")
    
    '''
    Retrieve the logs of the configuration of the existing s3 buckets
    '''
    def get_logs_s3(self):
        s3_list = self.services["s3"]

        if s3_list["count"] == -1:

            elements = s3_lookup()

            if len(elements) == 0:
                self.display_progress(0, "s3")
                return

        elif s3_list["count"] == 0:
            # if there is not bucket at all
            self.display_progress(0, "s3")
            return
        else:
            elements = s3_list["elements"]

        cnt = 0

        self.results["s3"]["action"] = 1
        self.results["s3"]["results"] = []
        
        for bucket in elements:
         
            name = bucket["Name"]

            logging = try_except(S3_CLIENT.get_bucket_logging, Bucket=name)
            
            if "LoggingEnabled" in logging:
                target = logging["LoggingEnabled"]["TargetBucket"]
                bucket = target.split(":")[-1]
                src_bucket = bucket.split("/")[0]

                if logging["LoggingEnabled"]["TargetPrefix"]:
                    prefix = logging["LoggingEnabled"]["TargetPrefix"]
                src_bucket = f"{src_bucket}|{prefix}"

                self.results["s3"]["results"].append(src_bucket)
             
                cnt += 1
       
        self.display_progress(cnt, "s3")
    
    '''
    Retrieve the logs of the configuration of the existing inspector coverages
    '''      
    def get_logs_inspector2(self):
        inspector_list = self.services["inspector"]

        if inspector_list["count"] == -1:

            covered = paginate(source.utils.INSPECTOR_CLIENT, "list_coverage", "coveredResources")

            if len(covered) == 0:
                self.display_progress(0, "inspector")
                return

        elif inspector_list["count"] == 0:
            self.display_progress(0, "inspector")
            return

        get_findings = simple_paginate(source.utils.INSPECTOR_CLIENT, "list_findings")

        get_grouped_findings = simple_paginate(
            source.utils.INSPECTOR_CLIENT, "list_finding_aggregations", aggregationType="TITLE"
        )

        results = []
        results.append(create_command("aws inspector2 list-findings", get_findings))
        results.append(
            create_command(
                "aws inspector2 list-finding-aggregations --aggregation-type TITLE",
                get_grouped_findings,
            )
        )

        self.results["inspector"]["action"] = 0
        self.results["inspector"]["results"] = results

        self.display_progress(len(results), "inspector")
    
    '''
    Retrieve the logs of the configuration of the existing macie buckets
    '''
    def get_logs_maciev2(self):
        macie_list = self.services["macie"]

        if macie_list["count"] == -1:

            elements = paginate(source.utils.MACIE_CLIENT, "describe_buckets", "buckets")

            if len(elements) == 0:
                self.display_progress(0, "macie")
                return
        elif macie_list["count"] == 0:
            self.display_progress(0, "macie")
            return

        get_list_findings = simple_paginate(source.utils.MACIE_CLIENT, "list_findings")

        response = try_except(
            source.utils.MACIE_CLIENT.get_findings,
            findingIds=get_list_findings.get("findingIds", []),
        )
        response.pop("ResponseMetadata", None)
        findings = fix_json(response)

        results = []
        results.append(create_command("aws macie2 list-findings", get_list_findings))
        results.append(
            create_command("aws macie2 get-findings --finding-ids <ID>", findings)
        )

        self.results["macie"]["action"] = 0
        self.results["macie"]["results"] = results

        self.display_progress(len(results), "macie")

    '''
    Create a role json
    '''
    def create_json(self):
        file_json = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        }

        with open(ROLE_JSON, "w") as f:
            json.dump(file_json, f)
        with open(ROLE_JSON, "r") as fr:
            data = fr.read()

        return data

    '''
    Create a ssm role
    '''
    def create_ssm_role(self):
        data = self.create_json()
        iam = source.utils.IAM_CLIENT
        role_name = "SSM_IR_Extraction01"
        instance_name = "SSM_S3_IR_Extraction01"

        try:
            new_role = iam.create_role(
                RoleName=role_name, Path="/./", AssumeRolePolicyDocument=data
            )

            policy_ssm = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            )

            policy_s3 = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
            )
        except Exception as e:
            if "EntityAlreadyExists" in str(e):
                pass
        try:
            create_instance_profile = iam.create_instance_profile(
                InstanceProfileName=instance_name
            )
            attach_role = iam.add_role_to_instance_profile(
                RoleName=role_name, InstanceProfileName=instance_name
            )
        except Exception as e:
            if "EntityAlreadyExists" in str(e):
                create_instance_profile = iam.get_instance_profile(
                    InstanceProfileName=instance_name
                )
            else:
                print(str(e))

        profile_for_replace = {}
        profile_for_replace["Arn"] = create_instance_profile["InstanceProfile"]["Arn"]
        profile_for_replace["Name"] = create_instance_profile["InstanceProfile"][
            "InstanceProfileName"
        ]
        os.remove(ROLE_JSON)

        return profile_for_replace
    '''
    Create an associated profile
    instanceid : Id of the instance to associate
    instance_prof : profile of the instance
    '''
    def associate_role(self, instanceid, instance_prof):
        associate_prof = source.utils.EC2_CLIENT.associate_iam_instance_profile(
            IamInstanceProfile={"Arn": instance_prof["Arn"], "Name": instance_prof["Name"]},
            InstanceId=instanceid
        )

        print(associate_prof)

    '''
    Retrieve the role and id of each instances
    '''
    def extract_role_and_id(self):
        list_instances_profiles = source.utils.EC2_CLIENT.describe_iam_instance_profile_associations()
        old_profiles = []
        profile = {}
        prof = {}

        for instance in list_instances_profiles["IamInstanceProfileAssociations"]:
            profile["instanceID"] = instance["InstanceId"]
            prof["Arn"] = instance["IamInstanceProfile"]["Arn"]
            prof["Name"] = instance["IamInstanceProfile"]["Arn"].split("/")[1].strip()
            profile["profileARN"] = prof
            profile["AssociatedID"] = instance["AssociationId"]
            old_profiles.append(profile)
            profile = {}
            prof = {}

        return old_profiles

    '''
    Update the profile
    iam_profile : new IAM profile
    associade_id : id associated to the IAM profile
    '''
    def replace_role(self, iam_profile, associate_id):
        new_profile = source.utils.EC2_CLIENT.replace_iam_instance_profile_association(
            IamInstanceProfile=iam_profile, AssociationId=associate_id
        )

        return new_profile

    '''
    Get the list of every ssm instances
    '''
    def extract_list_ssm_instances(self):
        ssm_instances = source.utils.SSM_CLIENT.describe_instance_information()
        total_ssm_instances = []

        for instance in ssm_instances["InstanceInformationList"]:
            total_ssm_instances.append(instance["InstanceId"])

        return total_ssm_instances
    
    '''
    Verify each 3 second if the command sent are finished or not
    instance_name : name of the instance we're verifying
    command_id : id of the sent command
    '''
    def wait_for_command_completion(self, instance_name, command_id):

        while True:
            response = source.utils.SSM_CLIENT.get_command_invocation(
                InstanceId=instance_name,
                CommandId=command_id,
            )

            status = response['Status']
            if status in ['Pending', 'InProgress']:
                time.sleep(5)  # Attendez 5 secondes avant de vérifier à nouveau
            else:
                break

    '''
    Extract logs of the defined log files.
    '''
    def extract_logs(self):
        list_of_logs = [
            "cat /var/log/syslog",
            "cat /var/log/messages",
            "cat /var/log/auth.log",
            "cat /var/log/secure",
            "cat /var/log/boot.log",
            "cat /var/log/dmesg",
            "cat /var/log/faillog",
            "cat /var/log/cron",
            "cat /var/log/kern.log",
        ]

        total_ssm_instances = self.extract_list_ssm_instances()

        if self.dl:
            create_folder(self.confs + "/ec2")
            send_command = source.utils.SSM_CLIENT.send_command(
            InstanceIds=total_ssm_instances,
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": list_of_logs},
            )

            command_id = send_command['Command']['CommandId']

            time.sleep(3)

            for instance in total_ssm_instances:

                self.wait_for_command_completion(instance, command_id)

                output = source.utils.SSM_CLIENT.get_command_invocation(
                    InstanceId=instance,
                    CommandId=command_id,
                )['StandardOutputContent']

                write_file(
                    self.confs + f"/ec2/{instance}_logs.json",
                    "w",
                    json.dumps(output, indent=4, default=str),
                )
        else:
            send_command = source.utils.SSM_CLIENT.send_command(
                InstanceIds=total_ssm_instances,
                DocumentName="AWS-RunShellScript",
                OutputS3BucketName=self.bucket,
                OutputS3KeyPrefix="ec2",
                Parameters={"commands": list_of_logs},
            )

    '''
    Change the profiles of the instances
    old_profiles : profiles to be changed
    fields : list of the instances
    IamInstanceProfile : new IAM instance profile
    '''
    def switch_profiles(self, old_profiles, fields, IamInstanceProfile):
        for profile in old_profiles:
            if fields["InstanceId"] == profile["instanceID"]:
                self.replace_role(IamInstanceProfile, profile["AssociatedID"])

    '''
    Define if we change the profile or create a new one
    profiles : list of the profiles to be changed
    instances : list of the instances
    IamInstanceProfile : new instance profile
    '''
    def new_profiles_instances(self, profiles, instances, IamInstanceProfile):
            for instance in instances:
                if "IamInstanceProfile" in instance:
                    self.switch_profiles(profiles, instance, IamInstanceProfile)
                else:
                    self.associate_role(instance["InstanceId"], IamInstanceProfile)

    '''
    Reset the profiles to the ones at the beginning
    old_profiles : old profiles to change
    new_profiles : profiles that will replace the old ones
    '''
    def back_to_normal(self, old_profiles, new_profiles):
        for old_profile in old_profiles:
            for new_profile in new_profiles:
                if old_profile["instanceID"] == new_profile["instanceID"]:
                    self.replace_role(
                        old_profile["profileARN"], new_profile["AssociatedID"]
                    )
    
    '''
    Retrieve the logs of the configuration of the existing ec2 instances
    '''
    def get_logs_ec2(self):
        ec2_list = self.services["ec2"] 

        if ec2_list["count"] == -1:
            instances = ec2_lookup()
            
            if len(instances) == 0:
                self.display_progress(0, "ec2")
                return

        elif ec2_list["count"] == 0:
            self.display_progress(0, "ec2")
            return
        else:
            instances = ec2_list["elements"]

        profile_for_replace = self.create_ssm_role()

        time.sleep(60)

        old_profiles = self.extract_role_and_id()
        self.new_profiles_instances(old_profiles, instances, profile_for_replace)

        time.sleep(60)

        self.extract_logs()
        new_profiles = self.extract_role_and_id()

        self.back_to_normal(old_profiles, new_profiles)
        self.display_progress(1, "ec2")

    '''
    "Download" the rds logs
    nameDB : name of the rds instance
    rds : RDS client
    logname : name of the logfile to get

    '''
    def download_rds(self, nameDB, rds, logname):
        response = try_except(
            rds.download_db_log_file_portion,
            DBInstanceIdentifier=nameDB,
            LogFileName=logname,
            Marker="0",
        )

        return response.get("LogFileData", "")
    
    '''
    Retrieve the logs of the configuration of the existing rds instances
    '''
    def get_logs_rds(self):
        rds_list = self.services["rds"]

        if rds_list["count"] == -1:

            list_of_dbs = paginate(source.utils.RDS_CLIENT, "describe_db_instances", "DBInstances")

            if len(list_of_dbs) == 0:
                self.display_progress(0, "rds")
                return

        elif rds_list["count"] == 0:
            self.display_progress(0, "rds")
            return
        else:
            list_of_dbs = rds_list["elements"]

        total_logs = []

        for db in list_of_dbs:
            total_logs.append(
                self.download_rds(
                    db["DBInstanceIdentifier"],
                    source.utils.RDS_CLIENT,
                    "external/mysql-external.log",
                )
            )
            total_logs.append(
                self.download_rds(
                    db["DBInstanceIdentifier"], source.utils.RDS_CLIENT, "error/mysql-error.log"
                )
            )

        self.results["rds"]["action"] = 0
        self.results["rds"]["results"] = total_logs

        self.display_progress(len(list_of_dbs), "rds")
    
    '''
    Retrieve the logs of the configuration of the existing routes53 hosted zones
    '''
    def get_logs_route53(self):
        route53_list = self.services["route53"]

        if route53_list["count"] == -1:
            
            hosted_zones = paginate(source.utils.ROUTE53_CLIENT, "list_hosted_zones", "HostedZones")

            if hosted_zones:
                self.display_progress(0, "route53")
                return

        elif route53_list["count"] == 0:
            self.display_progress(0, "route53")
            return

        resolver_log_configs = paginate(source.utils.ROUTE53_RESOLVER_CLIENT, "list_resolver_query_log_configs", "ResolverQueryLogConfigs")
        cnt = 0

        self.results["route53"]["action"] = 1
        self.results["route53"]["results"] = []

        for bucket_location in resolver_log_configs:
            if "s3" in bucket_location["DestinationArn"]:
                bucket = bucket_location["DestinationArn"].split(":")[-1]

                if "/" in bucket:

                    src_bucket = bucket.split("/")[0]
                    prefix = bucket.split("/")[1]
                    result = f"{src_bucket}|{prefix}"
                
                else :
                    result = bucket

                self.results["route53"]["results"].append(result)

                cnt += 1
                
        self.display_progress(cnt, "route53")

    '''
    Diplays if the configuration of the given service worked
    count : != 0 a configuration file was created. 0 otherwise
    name : Name of the service
    '''
    def display_progress(self, count, name):
        if count != 0:
            print(
                "         \u2705 "
                + name.upper()
                + "\033[1m"
                + " - Logs extracted"
                + "\033[0m"
            )
        else:
            print(
                "         \u274c " + name.upper() + "\033[1m" + " - No Logs" + "\033[0m"
            )
