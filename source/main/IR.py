from source.main.Enumeration import Enumeration
from source.main.Configuration import Configuration
from source.main.Logs import Logs
from source.main.Analysis import Analysis
from source.utils.utils import ENUMERATION_SERVICES, BOLD, ENDC

class IR:
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
        print(f"\n[+] Working on region {BOLD}{region}{ENDC}")

        
        if "4" in steps:
            self.a = Analysis(region, dl)
            if output != None:
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


    '''
    Run the enumeration main function
    regionless : "not-all" if the tool is used on only one region. First region to run the tool on otherwise
    '''
    def execute_enumeration(self, regionless):
        self.services = self.e.execute(self.services, regionless)

    '''
    Run the configuration main function
    regionless : "not-all" if the tool is used on only one region. First region to run the tool on otherwise    
    '''
    def execute_configuration(self, regionless):
        self.c.execute(self.services, regionless)

    '''
    Run the logs extraction main function
    regionless : "not-all" if the tool is used on only one region. First region to run the tool on otherwise    
    '''
    def execute_logs(self, regionless, start, end):
        self.l.execute(self.services, regionless, start, end)

    '''
    Run the logs analysis main function
    '''
    def execute_analysis(self, exists):
        self.a.execute(self.source, self.output, self.catalog, self.database, self.table, exists)