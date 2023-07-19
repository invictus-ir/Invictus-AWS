import argparse, os, sys

from source.IR import IR
from botocore.client import ClientError
from source.utils import ROOT_FOLDER, ACCOUNT_CLIENT, POSSIBLE_STEPS, try_except, create_folder


def set_args():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="[+] Show this help message and exit.",
    )

    parser.add_argument(
        "-s", 
        "--step", 
        nargs='?', 
        type=str, 
        const="1,2,3", 
        default="1,2,3", 
        help="[+] Comma separated list of the steps to be runned out. 1 - Enumeration. 2 - Configuration. 3 -    Logs Extraction. Default is 1,2,3"
    )

    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument(
        "-l",
        "--locally",
        action="store_true",
        help="[+] Download the results locally. Can't be used with -s",
    )
    group1.add_argument(
        "-c",
        "--cloud",
        action="store_true",
        help="[+] Set the results in a S3 bucket on the account. Needs extra permissions. Can't be used with -l.",
    )

    group2 = parser.add_mutually_exclusive_group(required=True)
    group2.add_argument(
        "-r",
        "--aws-region",
        help="[+] Only scan the specified region of the account. Can't be used with -a.",
    )
    group2.add_argument(
        "-a",
        "--all-regions",
        nargs="?",
        type=str,
        const="us-east-1",
        default="not-all",
        help="[+] Scan all the enabled regions of the account. If you specify a region, it will be used to store the regionless services. Can't be used with -r.",
    )

    return parser.parse_args()

def run_steps(dl, region, regionless, steps):

    if dl:
        create_folder(ROOT_FOLDER + "/" + region)
                      
    ir = IR(region, dl)

    try:
        ir.test_modules()
    except Exception as e: 
        print(str(e))
        sys.exit(-1)

    if "1" in steps:
        try:
            ir.execute_enumeration(regionless)
        except Exception as e: 
            print(str(e))

    if "2" in steps:
        try:
            ir.execute_configuration(regionless)
        except Exception as e: 
            print(str(e))
    
    if "3" in steps:
        try:
            ir.execute_logs(regionless)
        except Exception as e: 
            print(str(e))

def verify_all_regions(input_region):

    response = try_except(
        ACCOUNT_CLIENT.list_regions,
        RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"],
    )
    response.pop("ResponseMetadata", None)
    regions = response["Regions"]

    region_names = []

    for region in regions:
        region_names.append(region["RegionName"])

    regionless = ""
    if input_region in region_names:
        region_names.remove(input_region)
        region_names.insert(0, input_region)
        regionless = input_region

        return region_names, regionless
    else:
        print(
            "[!] Error : The region you entered doesn't exist or is not enabled. Please enter a valid region. Exiting..."
        )
        sys.exit(-1)

def verify_one_region(dl, region, all_regions, steps):
    try:
        response = ACCOUNT_CLIENT.get_region_opt_status(RegionName=region)
        response.pop("ResponseMetadata", None)
        if (
            response["RegionOptStatus"] == "ENABLED_BY_DEFAULT"
            or response["RegionOptStatus"] == "ENABLED"
        ):
            run_steps(dl, region, all_regions, steps)

    except Exception as e:
            print(str(e))
            sys.exit(-1)

def verify_steps(steps):
    for step in steps:
        if step not in POSSIBLE_STEPS:
            print(
            "[!] Error : The steps you entered are not allowed. Please enter only valid steps. Exiting..."
            )
            sys.exit(-1)

    return steps


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

    if os.getenv('AWS_EXECUTION_ENV') is not None and os.getenv('AWS_EXECUTION_ENV') == "CloudShell" and dl == True:
        dl = False
        print("[!] Error : You are in a Cloudshell environnement. Therefore you can't download your results locally. The results will be stored in a s3 bucket.")

    region = args.aws_region
    all_regions= args.all_regions
    steps = verify_steps(args.step.split(","))

    if region:

        verify_one_region(dl, region, all_regions, steps)
    
    else:
        
        region_names, regionless = verify_all_regions(all_regions)

        for name in region_names:
            run_steps(dl, name, regionless, steps)


if __name__ == "__main__":
    main()
