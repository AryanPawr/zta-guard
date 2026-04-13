# cli/main.py

import argparse
from core.orchestrator import run_scan

def main():
    parser = argparse.ArgumentParser(
        prog="zta",
        description="ZTA Guard - Zero Trust Auditor"
    )

    parser.add_argument(
        "command",
        choices=["scan"],
        help="Command to execute"
    )

    parser.add_argument(
        "--path",
        default=".",
        help="Project path"
    )

    parser.add_argument(
        "--target-url",
        help="Target URL for probing"
    )

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(path=args.path, target_url=args.target_url)

if __name__ == "__main__":
    main()