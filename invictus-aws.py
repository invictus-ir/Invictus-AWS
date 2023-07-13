import argparse, os, sys

from source.IR import IR
from botocore.client import ClientError
from source.utils import ROOT_FOLDER, ACCOUNT_CLIENT, try_except, create_folder


def set_args():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="[+] Show this help message and exit.",
    )

    group1 = parser.add_mutually_exclusive_group()
    group1.add_argument(
        "-l",
        "--locally",
        action="store_true",
        help="[+] Download the results locally. Can't be used with -s",
    )
    group1.add_argument(
        "-s",
        "--s3",
        action="store_true",
        help="[+] Set the results in a S3 bucket on the account. Needs extra permissions. Can't be used with -l.",
    )

    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument(
        "-r",
        "--aws-region",
        help="[+] Only scan the specified region of the account. Can't be used with -a.",
    )
    group2.add_argument(
        "-a",
        "--all-regions",
        action="store_true",
        help="[+] Scan all the enabled regions of the account. Can't be used with -r.",
    )

    return parser.parse_args()


def main():
    print(
        """
      _            _      _                                      
     (_)          (_)    | |                                     
      _ _ ____   ___  ___| |_ _   _ ___ ______ __ ___      _____ 
     | | '_ \ \ / / |/ __| __| | | / __|______/ _` \ \ /\ / / __|
     | | | | \ V /| | (__| |_| |_| \__ \     | (_| |\ V  V /\__ \\
     |_|_| |_|\_/ |_|\___|\__|\__,_|___/      \__,_| \_/\_/ |___/
                                                             
                                                             
     Copyright (c) 2022 Invictus Incident Response
     Authors: Antonio Macovei & Rares Bratean & Benjamin Guillouzo

    """
    )

    args = set_args()

    dl = args.locally
    region = args.aws_region

    if region:
        try:
            response = ACCOUNT_CLIENT.get_region_opt_status(RegionName=region)
            response.pop("ResponseMetadata", None)
            if (
                response["RegionOptStatus"] == "ENABLED_BY_DEFAULT"
                or response["RegionOptStatus"] == "ENABLED"
            ) and dl:
                create_folder(ROOT_FOLDER + region)

                ir = IR(region, dl)
                ir.test_modules()
                # ir.execute_enumeration()
                # ir.execute_configuration()
                ir.execute_logs()

        except ClientError:
            print(
                "[!] Error : The region you entered doesn't exist or is not enabled. Please enter a valid region. Exiting..."
            )
            sys.exit(-1)
    else:
        response = try_except(
            ACCOUNT_CLIENT.list_regions,
            RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"],
        )
        response.pop("ResponseMetadata", None)
        regions = response["Regions"]
        for region in regions:
            name = region["RegionName"]

            if dl:
                create_folder(ROOT_FOLDER + "/" + name)

            # ir = IR(name, dl)
            # ir.test_modules()
            # ir.execute_enumeration()
            # ir.execute_configuration()
            # ir.execute_logs()


if __name__ == "__main__":
    main()
