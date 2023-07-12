from source.Enumeration import Enumeration
from source.Configuration import Configuration
from source.Logs import Logs

import os


class IR:
    services = None
    e = None
    c = None
    l = None

    def __init__(self, region, dl):
        """
        -1 means we didn't enter in the enumerate function associated (either crash or just not yet)
        0 means we ran the associated function but the service wasn't available
        """
        self.services = {
            "s3": {"count": -1, "elements": [], "ids": []},
            "wafv2": {"count": -1, "elements": [], "ids": []},
            "lambda": {"count": -1, "elements": [], "ids": []},
            "vpc": {"count": -1, "elements": [], "ids": []},
            "elasticbeanstalk": {"count": -1, "elements": [], "ids": []},
            "route53": {"count": -1, "elements": [], "ids": []},
            "ec2": {"count": -1, "elements": [], "ids": []},
            "iam": {"count": -1, "elements": [], "ids": []},
            "dynamodb": {"count": -1, "elements": [], "ids": []},
            "rds": {"count": -1, "elements": [], "ids": []},
            "eks": {"count": -1, "elements": [], "ids": []},
            "els": {"count": -1, "elements": [], "ids": []},
            "secrets": {"count": -1, "elements": [], "ids": []},
            "kinesis": {"count": -1, "elements": [], "ids": []},
            "cloudwatch": {"count": -1, "elements": [], "ids": []},
            "guardduty": {"count": -1, "elements": [], "ids": []},
            "detective": {"count": -1, "elements": [], "ids": []},
            "inspector": {"count": -1, "elements": [], "ids": []},
            "macie": {"count": -1, "elements": [], "ids": []},
            "cloudtrail-logs": {"count": -1, "elements": [], "ids": []},
            "cloudtrail": {"count": -1, "elements": [], "ids": []},
        }

        self.e = Enumeration(region, dl)
        self.c = Configuration(region, dl)
        self.l = Logs(region, dl)

    def test_modules(self):
        self.e.self_test()
        self.c.self_test()
        self.l.self_test()

    def execute_enumeration(self):
        self.services = self.e.execute(self.services)

    def execute_configuration(self):
        self.c.execute(self.services)

    def execute_logs(self):
        self.l.execute(self.services)
