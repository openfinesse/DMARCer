#!/usr/bin/env python3
"""
DMARC Analyzer

Command-line entry point for the DMARC Analyzer when run directly.
"""

import sys
import os

# Add the src directory to the path if running directly from source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.cli import main

if __name__ == "__main__":
    main() 