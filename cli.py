import argparse
from scanner import analyze_target


def main():
    parser = argparse.ArgumentParser(description="PQC TLS Scanner")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--port", type=int, default=443, help="Port number")

    args = parser.parse_args()

    analyze_target(args.target, args.port)


if __name__ == "__main__":
    main()