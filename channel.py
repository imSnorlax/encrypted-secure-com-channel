#!/usr/bin/env python3
"""Entry point: python channel.py <command>"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from client.cli import cli
if __name__ == "__main__":
    cli(obj={})
