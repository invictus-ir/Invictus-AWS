Examples
========

**Acquire data exclusively from the eu-wests-3 region, excluding the Configuration step and store the output locally.** :  

``$python3 main.py -r eu-west-3 -s 1,3 -w local``  

*Mind that the CloudTrail logs, if existing, will be written both locally and in a S3 bucket as the analysis step needs the logs to be in a bucket.*

=========================

**Acquire data from all region, beginning by eu-west-3, with all the steps (1,2,3) and with results written in a S3 Bucket.** :   

``$python3 main.py -A eu-west-3``

=========================

**Analyze CloudTrail logs using the tool default database and table.** :  


``$python3 main.py -r eu-west-3 -s 4 -b bucket/path-to-the-existing-logs/ -o bucket/path-to-existing-folder-to-store-the-results/``  

*In this example, the -b option is needed the first time as the default database and table will be created. Then you don't need it anymore as the table is already initialized.  
But don't forget that if you modify your logs source and still want to use the default table, you need to delete it before.*

=========================

**Analyze CloudTrail logs using the tool default database and table, filter the results to the last 7 days and write the results locally.** :  

``$python3 main.py -r eu-west-3 -w local -s 4 -x 7`` 

*In this example, the -b option is not written as explained above. The -o option is also not written as we don't need any output bucket as the results will be written locally.*

=========================

**Analyze CloudTrail logs using either a new database or table (with the same structure as the default one)** :  

``$python3 main.py -r eu-west-3 -w -s 4 -b bucket/path-to-the-existing-logs/ -o bucket/path-to-existing-folder-to-store-the-results/ -c your-catalog -d your-database -t your-table``  

*In this example, the -b option is needed the first time as the default database and table will be created. Then you don't need it anymore as the table is already initialized.  
But don't forget that if you modify your logs source and still want to use the default table, you need to delete it before.**

=========================

**Analyze CloudTrail logs using your existing database and table, using your own query file** :  

``$python3 main.py -r eu-west-3 -s 4 -o bucket/path-to-existing-folder-where-to-put-the-results/ -c your-catalog -d your-database -t your-table -f path-to-existing-query-file``

=========================

**Analyze CloudTrail logs using a new table with your own structure.** :  

``$python3 main.py -a eu-west-3 -s 4 -s bucket/path-to-the-existing-logs/ -o bucket/path-to-existing-folder-where-to-put-the-results/ -c your-catalog -d your-database -t your-creation-table-file.ddl``  

*You can find an example of ddl file in `source/files`. Just replace the name of the table by the one you want to create, the location by the location of your CloudTrail logs and add the structure of your table. The default table used by the tool is explained here :* https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html .