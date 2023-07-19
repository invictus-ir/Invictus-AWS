from source.Enumeration import Enumeration
from source.Configuration import Configuration
from source.Logs import Logs
from source.utils import ENUMERATION_SERVICES

class IR:
    services = None
    e = None
    c = None
    l = None

    def __init__(self, region, dl):
        print(f"\n[+] Scanning region \033[1m{region}\033[0;0m\n")

        """
        -1 means we didn't enter in the enumerate function associated (either crash or just not yet)
        0 means we ran the associated function but the service wasn't available
        """
        self.services = ENUMERATION_SERVICES

        self.e = Enumeration(region, dl)
        self.c = Configuration(region, dl)
        self.l = Logs(region, dl)

    def test_modules(self):
        self.e.self_test()
        self.c.self_test()
        self.l.self_test()

    def execute_enumeration(self, regionless):
        self.services = self.e.execute(self.services, regionless)

    def execute_configuration(self, regionless):
        self.c.execute(self.services, regionless)

    def execute_logs(self, regionless):
        self.l.execute(self.services, regionless)
