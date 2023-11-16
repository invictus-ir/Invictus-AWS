How it works
============

The tool is divided into 4 different steps :

#. 1st step performs enumeration of activated AWS services and its details.
#. 2nd step retrieves configuration details about the activated services.
#. 3rd step extracts available logs for the activated services.
#. 4th step analyze CloudTrail logs, and only CloudTrail logs, by running Athena queries against it. 

.. note::

    Step 4 : 
    The queries are written in the file :samp:`source/files/queries.yaml`. 
    There are already some queries, but you can remove or add your own. If you add you own queries, be careful to respect this style :samp:`name-of-your-query ...FROM DATABASE.TABLE ...` , don't specify the database and table. 

    Step 4 : 
    The logs used by this step can be CloudTrail logs extracted by step 3 or your own CloudTrail logs. But there are some requirements about what the logs look like. They need to be stored in a S3 bucket in the default format (one JSON file, with a single line containing the event).

.. note::

    Each step can be run independently. There is no need to have completed step 1 to proceed with step 2.
