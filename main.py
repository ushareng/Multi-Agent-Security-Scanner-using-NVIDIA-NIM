#!/usr/bin/env python3
"""
main.py — Entry point for the Code Auditor pipeline.

Usage:
    python main.py --target ./my_project
    python main.py --target https://github.com/org/repo
    python main.py --target ./my_project --max-files 100 --output ./results

Requirements:
    1. Copy .env.example to .env
    2. Set your NVIDIA_API_KEY from https://build.nvidia.com (free tier)
    3. pip install -r requirements.txt
    4. python main.py --target <path_or_github_url>
"""

import argparse
import os
import sys
from dotenv import load_dotenv

load_dotenv()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Code Auditor — NIM-Powered Multi-Agent Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target ./my_project
  python main.py --target https://github.com/org/repo --max-files 30
  python main.py --target ./app --output ./audit_results --model mistralai/codestral-22b-instruct-v0.1
        """
    )
    parser.add_argument(
        "--target", required=True,
        help="Local path to codebase or GitHub URL to clone and audit"
    )
    parser.add_argument(
        "--max-files", type=int, default=50,
        help="Max files to scan (default: 50 — keep low for free NIM tier)"
    )
    parser.add_argument(
        "--output", default="./output",
        help="Output directory for reports (default: ./output)"
    )
    parser.add_argument(
        "--model", default=None,
        help="Override NIM model (default: meta/codellama-70b-instruct)"
    )
    parser.add_argument(
        "--skip-exploit", action="store_true",
        help="Skip PoC generation/execution (faster, no sandbox needed)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Apply CLI overrides to env
    os.environ["MAX_FILES"] = str(args.max_files)
    os.environ["OUTPUT_DIR"] = args.output
    if args.model:
        os.environ["NIM_MODEL"] = args.model
    if args.skip_exploit:
        os.environ["SKIP_EXPLOIT"] = "true"

    # Validate API key
    api_key = os.getenv("NVIDIA_API_KEY", "")
    if not api_key or api_key == "nvapi-YOUR_KEY_HERE":
        print("ERROR: NVIDIA_API_KEY not set.")
        print("  1. Get your free API key at: https://build.nvidia.com")
        print("  2. Copy .env.example to .env")
        print("  3. Set NVIDIA_API_KEY=nvapi-YOUR_ACTUAL_KEY")
        sys.exit(1)

    from orchestrator import Orchestrator
    orchestrator = Orchestrator(target=args.target)
    orchestrator.run()


if __name__ == "__main__":
    main()
