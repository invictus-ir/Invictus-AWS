from source.main.Enumeration import Enumeration
from source.main.Configuration import Configuration
from source.main.Logs import Logs
from source.utils import ENUMERATION_SERVICES, set_clients

class IR:
    services = None
    e = None
    c = None
    l = None

    def __init__(self, region, dl):
        print(f"\n[+] Scanning region \033[1m{region}\033[0;0m\n")

        self.services = ENUMERATION_SERVICES

        self.e = Enumeration(region, dl)
        self.c = Configuration(region, dl)
        self.l = Logs(region, dl)

    '''
    Run the test functions of the steps to be sure they're intialized and working
    '''
    def test_modules(self):
        self.e.self_test()
        self.c.self_test()
        self.l.self_test()

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
        self.l.execute(self.services, regionless)
