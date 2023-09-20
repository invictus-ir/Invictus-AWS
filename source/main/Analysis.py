import yaml, time, os, datetime, boto3
from source.utils.utils import athena_query, S3_CLIENT, rename_file_s3, get_table, set_clients, date, get_bucket_and_prefix, ENDC, OKGREEN, ROOT_FOLDER, create_folder
import source.utils.utils
import pandas as pd

class Analysis:
    source_bucket = None
    output_bucket = None
    region = None
    results = None
    dl = None
    path = None
    time = None

    def __init__(self, region, dl):

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
        
    '''
    Test function
    '''
    def self_test(self):
        print("[+] Logs Analysis test passed\n")

    '''
    Main function of the class. 
    '''
    def execute(self, source_bucket, output_bucket, catalog, db, table, exists):

        print(f"[+] Beginning Logs Analysis")

        set_clients(self.region)
        self.source_bucket = source_bucket
        
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
            db = "cloudtrailAnalysis"
            table = "logs"
        
        if not exists[0] or not exists[1]:
            self.init_athena(db, table, self.source_bucket, self.output_bucket, exists)

        try:
            with open('source/files/queries.yaml') as f:
                queries = yaml.safe_load(f)
        except Exception as e:
            print(f"[!] Error : {str(e)}")

        if not notNone:
            db = "cloudtrailAnalysis"
        elif table.endswith(".ddl"):
            table = get_table(table, False)[0]

        for key, value in queries.items():

            #replacing DATABASE and TABLE in each query
            value = value.replace("DATABASE", db)
            value = value.replace("TABLE", table)
            print(f"[+] Running Query : {key}")
            
            result = athena_query(self.region, value, self.output_bucket)

            id = result["QueryExecution"]["QueryExecutionId"]
            self.results_query(id, key)
            
            bucket, folder = get_bucket_and_prefix(self.output_bucket)

            time.sleep(1)
            done = True

            try:
                rename_file_s3(bucket, folder, f"{key}-output.csv", f'{id}.csv')
            except Exception as e:
                done = False

            while not done :
                try:
                    time.sleep(500/1000)
                    rename_file_s3(bucket, folder, f"{key}-output.csv", f'{id}.csv')
                    done = True
                except:
                    done = False  

        self.merge_results()
        self.clear_folder(self.dl)
    
    '''
    Initiates athena database and table for further analysis
    db : Database used
    table : Table used
    '''
    def init_athena(self, db, table, source_bucket, output_bucket, exists):

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
                ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
                LOCATION '{source_bucket}'  
        """
            athena_query(self.region, query_table, output_bucket)
            print(f"[+] Table {db}.{table} created")
        
    '''
    Replace the table name of the ddl file by database.table
    ddl: Ddl file
    db : Name of the db
    '''
    def set_table(self, ddl, db):
        table, data = get_table(ddl, True)

        if not "." in table:
            data = data.replace(table, f"{db}.{table}")

            with open(ddl, "wt") as f:
                f.write(data)
                f.close()
        return table

    '''
    Print the results of the query and where they are written
    id : Id of the query
    query : Run query
    '''
    def results_query(self, id, query):
    
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

    '''
    Merge the results csv files in one single xlsx file
    '''
    def merge_results(self):

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
            df = pd.read_csv(file, sep=",")
            df.to_excel(writer, sheet_name=sheet)

        writer.close()

        if not self.dl:

            S3_CLIENT.upload_file(writer, bucket_name, f'{prefix}{name_writer}')    
            os.remove(name_writer)
            for local_file_name in self.results:
                os.remove(local_file_name)

            print(f"[+] Results stored in {self.output_bucket}")
            print(f"[+] Merged results stored into {self.output_bucket}{name_writer}")

            self.results.append(name_writer)
        
        else:
            for local_file_name in self.results:
                os.replace(local_file_name, f"{self.path}{local_file_name}")
            os.replace(name_writer, f"{self.path}{name_writer}")
            print(f"[+] Results stored in {self.path}")
            print(f"[+] Merged results stored into {self.path}{name_writer}")
    

    '''
    Clear the results folder by removing the .txt, .metadata and also .csv files for queries without any results
    '''
    def clear_folder(self, dl):

        bucket, prefix = get_bucket_and_prefix(self.output_bucket)

        if dl:
            S3_CLIENT.delete_object(Bucket=bucket, Key=prefix)

            objets = S3_CLIENT.list_objects_v2(Bucket=bucket, Prefix=prefix)

            # Créez la liste des objets à supprimer
            objets_a_supprimer = [{'Key': obj['Key']} for obj in objets.get('Contents', [])]

            # Supprimez les objets en une seule requête
            if objets_a_supprimer:
                S3_CLIENT.delete_objects(Bucket=bucket, Delete={'Objects': objets_a_supprimer})

        else:
            
            resp = S3_CLIENT.list_objects_v2(Bucket=bucket, Prefix=prefix)

            for el in resp['Contents']:
                if not el["Key"].split("/")[-1] in self.results:
                    S3_CLIENT.delete_object(
                        Bucket=bucket,
                        Key=f"{el['Key']}"
                    )