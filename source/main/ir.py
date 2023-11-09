"""File used to run all the steps."""

from source.main.enumeration import Enumeration
from source.main.configuration import Configuration
from source.main.logs import Logs
from source.main.analysis import Analysis
from source.utils.utils import ENUMERATION_SERVICES, BOLD, ENDC

class IR:
    """IR Class that runs the differents functions needed.

    Attributes
    ----------
    services : dict
        Will contain data about the diffent steps
    e : object
        Enumeration object
    c : object
        Configuration object
    l : object
        Logs collection object
    a : object
        Analysis object
    source :  str
        Source bucket for the analysis part (4)
    output : str
        Output bucket for the analysis part (4)
    catalog : str
        Data catalog used with the database 
    database : str 
        Database containing the table for logs analytics
    table : str
        Contains the sql requirements to query the logs

    Methods
    -------
    execute_enumeration(regionless)
        Run the enumeration main function
    execute_configuration(regionless)
        Run the configuration main function
    execute_logs(regionless, start, end)
        Run the logs extraction main function
    execute_analysis(queryfile, exists, timeframe)
        Run the logs analysis main function
    """

    services = None
    e = None
    c = None
    l = None
    a = None
    source = None
    output = None
    catalog = None
    database = None
    table = None

    def __init__(self, region, dl, steps, source=None, output=None, catalog=None, database=None, table=None):
        """Handle the constructor of the IR class.
        
        Parameters
        ----------
        region : str
            Region in which to tool is executed
        dl : bool
            True if the user wants to download the results, False if he wants the results to be written in a s3 bucket
        steps : list of str
            Steps to run (1 for enum, 2 for config, 3 for logs extraction, 4 for analysis)
        source :  str, optional
            Source bucket for the analysis part (4)
        output : str, optional
            Output bucket for the analysis part (4)
        catalog : str, optional
            Data catalog used with the database 
        database : str , optional
            Database containing the table for logs analytics
        table : str, optional
            Contains the sql requirements to query the logs
        """
        print(f"\n[+] Working on region {BOLD}{region}{ENDC}")
        
        if "4" in steps:
            self.a = Analysis(region, dl)
            if source != None:
                self.source = source
            if output != None:
                self.output = output
            if catalog != None:
                self.catalog = catalog
            if database != None:
                self.database = database
            if table != None:
                self.table = table
        else:
            self.services = ENUMERATION_SERVICES

            if "1" in steps:
                self.e = Enumeration(region, dl)
            if "2" in steps:
                self.c = Configuration(region, dl)
            if "3" in steps:
                self.l = Logs(region, dl)

    def execute_enumeration(self, regionless):
        """Run the enumeration main function.
        
        Parameters
        ----------
        regionless : str
            'not-all' if the tool is used on only one region. First region to run the tool on otherwise
        """
        self.services = self.e.execute(self.services, regionless)

    def execute_configuration(self, regionless):
        """Run the configuration main function.
        
        Parameters
        ----------
        regionless : str
            'not-all' if the tool is used on only one region. First region to run the tool on otherwise
        """
        self.c.execute(self.services, regionless)

    def execute_logs(self, regionless, start, end):
        """Run the logs extraction main function.
        
        Parameters
        ----------
        regionless : str
            'not-all' if the tool is used on only one region. First region to run the tool on otherwise
        start : str
            Start date of the logs collected
        end : str
            End date of the logs collected
        """
        self.l.execute(self.services, regionless, start, end)

    def execute_analysis(self, queryfile, exists, timeframe):
        """Run the logs analysis main function.
        
        Parameters
        ----------
        queryfile : str
            File containing the queries to run
        exists : tuple of bool
            Array containing information about if the db and table exists
        timeframe : str
            Timeframe used in the query to filter results
        """
        self.a.execute(self.source, self.output, self.catalog, self.database, self.table, queryfile, exists, timeframe)