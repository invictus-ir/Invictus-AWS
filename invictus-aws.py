import argparse, sys, os
from source.IR import IR

from source.utils import try_except, ROOT_FOLDER, ACCOUNT_CLIENT


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


def create_folder(path):
    if not os.path.exists(path):
        os.mkdir(path)
    else:
        print("[!] Error : Folder {path} already exists")


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

    region = args.region

    if region is None:
        print(
            "Error: Invalid syntax\n\t--region=<aws_region> is required to run the script"
        )
        sys.exit(-1)
    ir = IR(region)
    # ir.test_modules()
    ir.execute_enumeration()
    ir.execute_configuration()
    ir.execute_logs()


if __name__ == "__main__":
    main()
