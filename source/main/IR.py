from source.main.Enumeration import Enumeration
from source.main.Configuration import Configuration
from source.main.Logs import Logs
from source.main.Analysis import Analysis
from source.utils import ENUMERATION_SERVICES, set_clients

class IR:
    services = None
    e = None
    c = None
    l = None
    a = None
    source = None
    output = None

    def __init__(self, region, dl, steps, source=None, output=None):
        print(f"\n[+] Working on region \033[1m{region}\033[0;0m")

        self.services = ENUMERATION_SERVICES

        if "1" in steps:
            self.e = Enumeration(region, dl)
        if "2" in steps:
            self.c = Configuration(region, dl)
        if "3" in steps:
            self.l = Logs(region, dl)
        if "4" in steps:
            self.a = Analysis(region)
            if source != None:
                self.source = source
            if output != None:
                self.output = output


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
    def execute_logs(self, regionless):
        source, output = self.l.execute(self.services, regionless)
        if self.source == None:
            self.source = source
        if self.output == None:
            self.output = output

    def execute_analysis(self):
        self.a.execute(self.source, self.output)