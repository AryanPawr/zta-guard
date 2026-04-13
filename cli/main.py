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

    args = parser.parse_args()

    if args.command == "scan":
        run_scan()

if __name__ == "__main__":
    main()