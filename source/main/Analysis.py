import boto3, yaml, time
from source.utils import athena_query, S3_CLIENT, rename_file_s3

class Analysis:
    source_bucket = None
    output_bucket = None
    region = None

    def __init__(self, region):

        self.region = region
        
    '''
    Test function
    '''
    def self_test(self):
        print("[+] Logs Analysis test passed\n")

    '''
    Main function of the class. 
    '''
    def execute(self, source_bucket, output_bucket):

        self.source_bucket = source_bucket
        self.output_bucket = output_bucket
        
        db = "`cloudtrail-analysis`"
        table = "logs"

        self.init_athena(db, table)

        try:
            with open('source/queries.yaml') as f:
                queries = yaml.safe_load(f)
        except Exception as e:
            print(f"[!] Error : {str(e)}")

        db = '"cloudtrail-analysis"'

        for key, value in queries.items():
            value = value.replace("DATABASE", db)
            value = value.replace("TABLE", table)
            print(value)
            result = athena_query(self.region, value, self.output_bucket)

            id = result["QueryExecution"]["QueryExecutionId"]
            bucket_list = output_bucket.split("/")

            bucket = bucket_list[2]
            folder = ""
            if len(bucket_list) == 5:
                folder = f"{bucket_list[3]}/"

            time.sleep(1)
            done = True

            try:
                rename_file_s3(bucket, folder, f"{key}.csv", f'{id}.csv')
            except Exception as e:
                done = False

            while not done :
                try:
                    time.sleep(500/1000)
                    rename_file_s3(bucket, folder, f"{key}.csv", f'{id}.csv')
                    done = True
                except:
                    done = False  
    
    '''
    Initiates athena database and table for further analysis
    '''
    def init_athena(self, db, table):
        query_db = f"CREATE DATABASE IF NOT EXISTS {db};"
        athena_query(self.region, query_db, self.output_bucket)

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
            ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
            LOCATION '{self.source_bucket}'  
        """
        athena_query(self.region, query_table, self.output_bucket)
