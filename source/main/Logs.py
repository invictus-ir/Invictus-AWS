import boto3, os, time, requests, json

import source.utils.utils
from source.utils.utils import write_file, create_folder, copy_or_write_s3, create_command, writefile_s3, LOGS_RESULTS, create_s3_if_not_exists, LOGS_BUCKET, ROOT_FOLDER, set_clients, write_or_dl, write_s3, athena_query
from source.utils.enum import *


class Logs:
    bucket = None
    region = None
    dl = None
    confs = None
    results = None

    def __init__(self, region, dl):

        self.region = region
        self.results = LOGS_RESULTS
        self.dl = dl

        #Also created for cloudtrail-logs results
        self.confs = ROOT_FOLDER + self.region + "/logs"
        self.bucket = create_s3_if_not_exists(self.region, LOGS_BUCKET)

        if self.dl:
            create_folder(self.confs)
        
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
        
        print(f"[+] Beginning Logs Extraction")

        set_clients(self.region)

        self.services = services
        source_bucket = ""
        output_bucket = ""

        if regionless == self.region or regionless == "not-all":
            self.get_logs_s3()
            self.get_logs_cloudtrail_logs()

        self.get_logs_wafv2()
        self.get_logs_vpc()
        self.get_logs_elasticbeanstalk()
    
        self.get_logs_route53()
        self.get_logs_rds()

        self.get_logs_cloudwatch()
        self.get_logs_guardduty()
        self.get_logs_inspector2()
        self.get_logs_maciev2()

        if self.dl:
            for key, value in self.results.items():
                if value["results"] and key != "cloudtrail-logs":
                    write_or_dl(key, value, self.confs)
                elif key == "cloudtrail-logs":
                    for el in value["results"]:
                        trail = el["CloudTrailEvent"]
                        obj = json.loads(trail)
                        dump = json.dumps(obj, default=str)
                        create_folder(f"{self.confs}/cloudtrail-logs/")
                        write_file(
                            f"{self.confs}/cloudtrail-logs/{obj['eventID']}.json",
                            "w",
                            dump,
                        )

        else:
            for key, value in self.results.items():
                if value["results"] and key != "cloudtrail-logs":
                    copy_or_write_s3(key, value, self.bucket, self.region)

        # cloudtrail-logs has to be done in any case for further analysis
        if self.results["cloudtrail-logs"]["results"]:
            res = self.results["cloudtrail-logs"]["results"]

            for el in res:

                trail = el["CloudTrailEvent"]
                obj = json.loads(trail)
                dump = json.dumps(obj, default=str)
                write_s3(
                    self.bucket,
                    f"{self.region}/logs/cloudtrail-logs/{obj['eventID']}.json",
                    dump,
                ) 

            print(f"[+] Logs extraction results stored in the bucket {self.bucket}")    
            source_bucket, output_bucket = self.init_athena()

            ret1 = source_bucket
            ret2 = output_bucket
        else:
            ret1 = "0"
            ret2 = "0"
            print(f"[+] Logs extraction results stored in the bucket {self.bucket}")

        
        return ret1, ret2
        
        
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
            detector_ids = paginate(source.utils.utils.GUARDDUTY_CLIENT, "list_detectors", "DetectorIds")

            if len(detector_ids) == 0:
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
            findings = paginate(source.utils.utils.GUARDDUTY_CLIENT, "list_findings", "FindingIds", DetectorId=detector)

            response = try_except(
                source.utils.utils.GUARDDUTY_CLIENT.get_findings, DetectorId=detector, FindingIds=findings
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

        logs = paginate(source.utils.utils.CLOUDTRAIL_CLIENT, "lookup_events", "Events")

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
            wafs = misc_lookup(source.utils.utils.WAF_CLIENT.list_web_acls, "NextMarker", "WebACLs", Scope="REGIONAL", Limit=100)

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
            logging = try_except(source.utils.utils.WAF_CLIENT.get_logging_configuration, ResourceArn=arn)
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
            vpcs = paginate(source.utils.utils.EC2_CLIENT, "describe_vpcs", "Vpcs")

            if len(vpcs) == 0:
                self.display_progress(0, "vpc")
                return

        elif vpc_list["count"] == 0:
            self.display_progress(0, "vpc")
            return

        flow_logs = paginate(source.utils.utils.EC2_CLIENT, "describe_flow_logs", "FlowLogs")
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

            environments = paginate(source.utils.utils.EB_CLIENT, "describe_environments", "Environments")

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
            dashboards = paginate(source.utils.utils.CLOUDWATCH_CLIENT, "list_dashboards", "DashboardEntries")

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
                source.utils.utils.CLOUDWATCH_CLIENT.get_dashboard, DashboardName=dashboard_name
            )
            response.pop("ResponseMetadata", None)
            dashboards_data[dashboard_name] = fix_json(response)

        metrics = try_except(source.utils.utils.CLOUDWATCH_CLIENT, "list_metrics")

        alarms = simple_paginate(source.utils.utils.CLOUDWATCH_CLIENT, "describe_alarms")

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

            covered = paginate(source.utils.utils.INSPECTOR_CLIENT, "list_coverage", "coveredResources")

            if len(covered) == 0:
                self.display_progress(0, "inspector")
                return

        elif inspector_list["count"] == 0:
            self.display_progress(0, "inspector")
            return

        get_findings = simple_paginate(source.utils.utils.INSPECTOR_CLIENT, "list_findings")

        get_grouped_findings = simple_paginate(
            source.utils.utils.INSPECTOR_CLIENT, "list_finding_aggregations", aggregationType="TITLE"
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

            elements = paginate(source.utils.utils.MACIE_CLIENT, "describe_buckets", "buckets")

            if len(elements) == 0:
                self.display_progress(0, "macie")
                return
        elif macie_list["count"] == 0:
            self.display_progress(0, "macie")
            return

        get_list_findings = simple_paginate(source.utils.utils.MACIE_CLIENT, "list_findings")

        response = try_except(
            source.utils.utils.MACIE_CLIENT.get_findings,
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

            list_of_dbs = paginate(source.utils.utils.RDS_CLIENT, "describe_db_instances", "DBInstances")

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
                    source.utils.utils.RDS_CLIENT,
                    "external/mysql-external.log",
                )
            )
            total_logs.append(
                self.download_rds(
                    db["DBInstanceIdentifier"], source.utils.utils.RDS_CLIENT, "error/mysql-error.log"
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
            
            hosted_zones = paginate(source.utils.utils.ROUTE53_CLIENT, "list_hosted_zones", "HostedZones")

            if hosted_zones:
                self.display_progress(0, "route53")
                return

        elif route53_list["count"] == 0:
            self.display_progress(0, "route53")
            return

        resolver_log_configs = paginate(source.utils.utils.ROUTE53_RESOLVER_CLIENT, "list_resolver_query_log_configs", "ResolverQueryLogConfigs")
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
    Initiates athena database and table for further analysis
    '''
    def init_athena(self):

        source_bucket = f"s3://{self.bucket}/{self.region}/logs/cloudtrail-logs/"
        output_bucket = f"s3://{self.bucket}/cloudtrail-analysis/"

        query_db = "create database if not exists `cloudtrailanalysis`;"
        athena_query(self.region, query_db, output_bucket)
        print(f"[+] Database cloudtrailanalysis created")
        
        query_table = f"""
            CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrailAnalysis.logs (
            eventversion STRING,
            useridentity STRUCT<
                           type:STRING,
                           principalid:STRING,
                           arn:STRING,
                           accountid:STRING,
                           invokedby:STRING,
                           accesskeyid:STRING,
                           userName:STRING,
              sessioncontext:STRUCT<
                attributes:STRUCT<
                           mfaauthenticated:STRING,
                           creationdate:STRING>,
                sessionissuer:STRUCT<  
                           type:STRING,
                           principalId:STRING,
                           arn:STRING, 
                           accountId:STRING,
                           userName:STRING>,
                ec2RoleDelivery:string,
                webIdFederationData:map<string,string>
              >
            >,
            eventtime STRING,
            eventsource STRING,
            eventname STRING,
            awsregion STRING,
            sourceipaddress STRING,
            useragent STRING,
            errorcode STRING,
            errormessage STRING,
            requestparameters STRING,
            responseelements STRING,
            additionaleventdata STRING,
            requestid STRING,
            eventid STRING,
            resources ARRAY<STRUCT<
                           arn:STRING,
                           accountid:STRING,
                           type:STRING>>,
            eventtype STRING,
            apiversion STRING,
            readonly STRING,
            recipientaccountid STRING,
            serviceeventdetails STRING,
            sharedeventid STRING,
            vpcendpointid STRING,
            tlsDetails struct<
              tlsVersion:string,
              cipherSuite:string,
              clientProvidedHostHeader:string>
            )
            ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
            LOCATION '{source_bucket}'  
        """
        athena_query(self.region, query_table, output_bucket)
        print(f"[+] Table cloudtrailanalysis.logs created")

        return source_bucket, output_bucket

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
