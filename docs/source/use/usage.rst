Usage
=====

Default Usage : ``python3 invictus-aws.py`` will get you into a walkthrough mode  

Power User Usage : ``python3 invictus-aws.py [-h] [-p profile] -w [{cloud,local}] (-r AWS_REGION | -A [ALL_REGIONS]) -s [STEP] [-start YYYY-MM-DD] [-end YYYY-MM-DD] [-b SOURCE_BUCKET] [-o OUTPUT_BUCKET][-c CATALOG] [-d DATABASE] [-t TABLE] [-f QUERY_FILE] [-x TIMEFRAME]``

The script runs with a few parameters :  

* ``-h`` to print out the help menu.
* ``-p profile`` or ``--profile profile``. Specify your aws profile. Default is ``default``.
* ``-w cloud`` or ``-w local``. 'cloud' option if you want the results to be stored in a S3 bucket (automatically created). 'local' option if you want the results to be written to local storage. The default option is 'cloud'. So if you want to use 'cloud' option, you can either write nothing, write only `-w` or write `-w cloud`.
* ``-r region`` or ``-a [region]``. Use the first option if you want the tool to analyze only the specified region. Use the second option if you want the tool to analyze all regions. You can also specify a region if you want to start with that one.
* ``-s [step,step]``. Provide a comma-separated list of the steps to be executed. 1 = Enumeration. 2 = Configuration. 3 = Logs Extraction. 4 = Logs Analysis. The default option is 1,2,3 as **step 4 has to be executed alone**. So if you want to run the three first steps, you can either write nothing, write only `-s` or write `-s 1,2,3`. If you want to run step 4, then write `-s 4`.
* ``-start YYYY-MM-DD``. Start date for the Cloudtrail logs collection. It is recommended to use it every time step 3 is executed as it will be extremely long to collect each logs. It has to be used with `-end` and must only be used with step 3.
* ``-end YYYY-MM-DD``. End date for the Cloudtrail logs collection. It is recommended to use it every time step 3 is executed as it will be extremely long to collect each logs. It has to be used with `-start` and must only be used with step 3.

.. note::

    The next parameters only apply if you run step 4. You have to collect the logs with step 3 on another execution or by your own means.

* ``-b bucket``. Bucket containing the CloudTrail logs. Format is ``bucket/subfolders/``.
* ``-o bucket``. Bucket where the results of the queries will be stored. Must look like ``bucket/[subfolders]/``.
* ``-c catalog``. Catalog used by Athena.
* ``-d database``. Database used by Athena. You can either input an existing database or a new one that will be created.
* ``-t table``. Table used by Athena. You can either input an existing table, input a new one (that will have the same structure as the default one) or input a .ddl file giving details about your new table. An example.ddl is available for you, just add the structure, modify the name of the table and the location of your logs.
* ``-f file.yaml``. Your own file containing your queries for the analysis. If you don't want to use or modify the default file, you can use your own by specifying it with this option. The file has to already exist.  
* ``-x timeframe``. Used by the queries to filter their results. The query part with the timeframe will automatically be added at the end of your queries if you specify a timeframe. You don't have to add it yourself to your queries.

