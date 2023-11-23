"""File used for the analysis."""

import yaml, datetime
from source.utils.utils import athena_query, S3_CLIENT, rename_file_s3, get_table, set_clients, date, get_bucket_and_prefix, ENDC, OKGREEN, ROOT_FOLDER, create_folder, create_tmp_bucket, get_random_chars
import source.utils.utils
from source.utils.enum import paginate
import pandas as pd
from os import remove, replace
from time import sleep


class Analysis:

    source_bucket = None
    output_bucket = None
    region = None
    results = None
    dl = None
    path = None
    time = None

    def __init__(self, region, dl):
        """Handle the constructor of the Analysis class.
        
        Parameters
        ----------
        region : str
            Region in which to tool is executed
        dl : bool
            True if the user wants to download the results, False if he wants the results to be written in a s3 bucket
        """
        self.region = region
        self.results = []
        self.dl = dl

        #new folder for each run
        now = datetime.datetime.now()
        self.time = now.strftime("%H:%M:%S")

        if dl:
            self.path = ROOT_FOLDER + self.region + "/queries-results/"
            self.path = f"{self.path}{date}/{self.time}/" 
            create_folder(self.path)
        
    def self_test(self):
        """Test function."""
        print("[+] Logs Analysis test passed\n")

    def execute(self, source_bucket, output_bucket, catalog, db, table, queryfile, exists, timeframe):
        """Handle the main function of the class.
        
        Parameters
        ----------
        source_bucket :  str
            Source bucket
        output_bucket : str
            Output bucket
        catalog : str
            Data catalog used with the database 
        db : str 
            Database containing the table for logs analytics
        table : str
            Contains the sql requirements to query the logs
        queryfile : str
            File containing the queries
        exists : tuple of bool
            If the input db and table already exists
        timeframe : str
            Time filter for default queries
        """
        print(f"[+] Beginning Logs Analysis")

        set_clients(self.region)
        self.source_bucket = source_bucket

        if output_bucket == None:
            rand_str = get_random_chars(5)
            tmp_bucket = f"invictus-aws-tmp-results-{rand_str}"
            create_tmp_bucket(self.region, tmp_bucket)
            output_bucket = f"s3://{tmp_bucket}/"
            print(output_bucket)
    
        bucket, prefix = get_bucket_and_prefix(output_bucket)
        if not prefix:
            prefix = "queries-results/"
            self.output_bucket = f"{output_bucket}{prefix}{date}/{self.time}/"
            S3_CLIENT.put_object(Bucket=bucket, Key=(f"{prefix}{date}/{self.time}/"))
        else:
            self.output_bucket = f"{output_bucket}{date}/{self.time}/"
      
        #True if not using tool default db and table
        notNone = False
        if (catalog != None and db != None and table != None):
            notNone = True 
        else:
            catalog = "AwsDataCatalog"
            db = "cloudtrailAnalysis"
            table = "logs"
        
        isTrail = self.is_trail_bucket(catalog, db, table)

        if not exists[0] or not exists[1]:
           self.init_athena(db, table, self.source_bucket, self.output_bucket, exists, isTrail)

        try:
            with open(queryfile) as f:
                queries = yaml.safe_load(f)
                print(f"[+] Using query file : {queryfile}")
        except Exception as e:
            print(f"[!] Error : {str(e)}")

        if not notNone:
            db = "cloudtrailAnalysis"
        elif table.endswith(".ddl"):
            table = get_table(table, False)[0]      

        #Running all the queries
        
        for key, value in queries.items():

            if timeframe != None:
                link = "AND"
                if "WHERE" not in value:
                    link = "WHERE"
                if value[-1] == ";":
                    value = value.replace(value[-1], f" {link} date_diff('day', from_iso8601_timestamp(eventtime), current_timestamp) <= {timeframe};")
                else:
                    value = value + f" {link} date_diff('day', from_iso8601_timestamp(eventtime), current_timestamp) <= {timeframe};"
          
            print(f"[+] Running Query : {key}")
            #replacing DATABASE and TABLE in each query
            value = value.replace("DATABASE", db)
            value = value.replace("TABLE", table)

            result = athena_query(self.region, value, self.output_bucket)

            id = result["QueryExecution"]["QueryExecutionId"]
            self.results_query(id, key)
            
            bucket, folder = get_bucket_and_prefix(self.output_bucket)

            sleep(1)
            done = True

            try:
                rename_file_s3(bucket, folder, f"{key}-output.csv", f'{id}.csv')
            except Exception as e:
                done = False

            while not done :
                try:
                    sleep(500/1000)
                    rename_file_s3(bucket, folder, f"{key}-output.csv", f'{id}.csv')
                    done = True
                except:
                    done = False  

        self.merge_results()
        self.clear_folder(self.dl)
    
    def init_athena(self, db, table, source_bucket, output_bucket, exists, isTrail):
        """Initiate athena database and table for further analysis.

        Parameters
        ----------
        db : str
            Database used
        table : str
            Table used
        source_bucket : str
            Source bucket of the logs of the table
        output_bucket : str
            Bucket where to put the results of the queries
        exists : bool
            If the given db and table already exists
        isTrail : bool
            if the source bucket of the table is a bucket trail
        """
        # if db doesn't exists
        if not exists[0]:
            query_db = f"CREATE DATABASE IF NOT EXISTS {db};"
            athena_query(self.region, query_db, self.output_bucket)
            print(f"[+] Database {db} created")

        #if table doesn't exists
        if not exists[1]:
            if table.endswith(".ddl"):
                tb = self.set_table(table, db)
                with open(table) as ddl:
                    query_table = ddl.read()
                    athena_query(self.region, query_table, self.output_bucket)
                print(f"[+] Table {tb} created")
            elif not isTrail:
                query_table = f"""
                    CREATE EXTERNAL TABLE IF NOT EXISTS {db}.{table} (
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
                    ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
                    LOCATION '{source_bucket}'   
                """
            else:
                query_table = f"""
                    CREATE EXTERNAL TABLE IF NOT EXISTS {db}.{table} (
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
                    ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
                    STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
                    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
                    LOCATION '{source_bucket}'
                """  

            athena_query(self.region, query_table, output_bucket)
            print(f"[+] Table {db}.{table} created")
   
    def set_table(self, ddl, db):
        """Replace the table name of the ddl file by database.table.

        Parameters
        ----------
        ddl : str
            Ddl file
        db : str
            Name of the db

        Returns 
        -------
        table : str
            Name of the table
        """
        table, data = get_table(ddl, True)

        if not "." in table:
            data = data.replace(table, f"{db}.{table}")

            with open(ddl, "wt") as f:
                f.write(data)
                f.close()
        return table

    def results_query(self, id, query):
        """Print the results of the query and where they are written.
        
        Parameters
        ----------
        id : str
            Id of the query
        query : str
        Query run
        """
        number   = len(source.utils.utils.ATHENA_CLIENT.get_query_results(QueryExecutionId=id)["ResultSet"]["Rows"])
        if number == 2:
            print(f"[+] {OKGREEN}{number-1} hit !{ENDC}")
            self.results.append(f"{query}-output.csv")
        elif number > 999:
            print(f"[+] {OKGREEN}{number-1}+ hits !{ENDC}")
            self.results.append(f"{query}-output.csv")
        elif number > 2:
            print(f"[+] {OKGREEN}{number-1} hits !{ENDC}")
            self.results.append(f"{query}-output.csv")
        else:
            print(f"[+] {number-1} hit. You may have better luck next time my young padawan !")

    def merge_results(self):
        """Merge the results csv files in one single xlsx file."""
        if self.results:

            bucket_name, prefix = get_bucket_and_prefix(self.output_bucket)

            name_writer = f"merged_file.xlsx"
            writer = pd.ExcelWriter(name_writer, engine='xlsxwriter')

            for local_file_name in self.results:
                s3_file_name = prefix + local_file_name
                S3_CLIENT.download_file(bucket_name, s3_file_name, local_file_name)


            for i, file in enumerate(self.results):
                sheet = str(file)[:-4]
                if len(sheet) > 31:
                    sheet = sheet[:24] + sheet[-7:]
                df = pd.read_csv(file, sep=",", dtype="string")
                df.to_excel(writer, sheet_name=sheet)

            writer.close()

            if not self.dl:

                S3_CLIENT.upload_file(writer, bucket_name, f'{prefix}{name_writer}')    
                remove(name_writer)
                for local_file_name in self.results:
                    remove(local_file_name)

                print(f"[+] Results stored in {self.output_bucket}")
                print(f"[+] Merged results stored into {self.output_bucket}{name_writer}")

                self.results.append(name_writer)

            else:
                for local_file_name in self.results:
                    replace(local_file_name, f"{self.path}{local_file_name}")
                replace(name_writer, f"{self.path}{name_writer}")
                print(f"[+] Results stored in {self.path}")
                print(f"[+] Merged results stored into {self.path}{name_writer}")
        else:
            print(f"[+] No results at all were found")
    
    def clear_folder(self, dl):
        """If results written locally, delete the tmp bucket created for the analysis. If results written in a bucket, clear the bucket so the .metadata and .txt are deleted.

        Parameters
        ----------
        dl : bool
            True if the user wants to download the results, False if he wants the results to be written in a s3 bucket
        """
        bucket, prefix = get_bucket_and_prefix(self.output_bucket)

        if dl:
            res = paginate(S3_CLIENT, "list_objects_v2", "Contents", Bucket=bucket)

            if res:
                objects = [{'Key': obj['Key']} for obj in res]
                S3_CLIENT.delete_objects(Bucket=bucket, Delete={'Objects': objects})

            try:
                S3_CLIENT.delete_bucket(
                    Bucket=bucket
                )
            except Exception as e:
                print(f"[!] Error : {str(e)}")

        else:
            
            res = paginate(S3_CLIENT, "list_objects_v2", "Contents", Bucket=bucket, Prefix=prefix)

            if res:
                for el in res:
                    if not el["Key"].split("/")[-1] in self.results:
                        S3_CLIENT.delete_object(
                            Bucket=bucket,
                            Key=f"{el['Key']}"
                        )

    def is_trail_bucket(self, catalog, db, table):
        """Verify if a table source bucket is a trail bucket.
        
        Parameters
        ----------
        catalog : str
            Catalog of the database and table
        db : str
            Database of the table
        table : str
            Table of the logs

        Returns
        -------
        isTrail : bool
            if the trail has a specified bucket
        """
        isTrail = False

        if self.source_bucket != None:

            response = source.utils.utils.CLOUDTRAIL_CLIENT.describe_trails()
            if response['trailList']:
                trails = response['trailList'] 

                for trail in trails:
                    logging_info = trail['S3BucketName']

                    if logging_info and logging_info in self.source_bucket:
                        isTrail = True
                        src = self.source_bucket
                        print("[!] Warning : You are using a trail bucket as source. Be aware these buckets can have millions of logs and so the tool can take a lot of time to process it all. Use the most precise subfolder available to be more efficient.")  
                        break
        else:
            response = source.utils.utils.ATHENA_CLIENT.get_table_metadata(
                CatalogName=catalog,
                DatabaseName=db,
                TableName=table
            )

            if response["TableMetadata"]["Parameters"]["inputformat"] == "com.amazon.emr.cloudtrail.CloudTrailInputFormat":
                isTrail = True
        
        return isTrail

    