"""
DMARC Analyzer Command-Line Interface

This module provides the command-line interface for the DMARC Analyzer,
handling argument parsing and the main program flow.
"""

import os
import sys
import glob
import argparse
from datetime import datetime

from parsers.dmarc_parser import extract_xml_from_file, parse_dmarc_report
from analysis.analyzer import analyze_reports
from reporting.text_report import generate_report
from reporting.html_report import generate_html_report


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Analyze DMARC reports in a directory')
    parser.add_argument('directory', help='Directory containing DMARC reports')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--html', action='store_true', help='Generate HTML report')
    parser.add_argument('--html-output', help='HTML output file (default: dmarc_report.html)')
    parser.add_argument('--resolve-ips', '-r', action='store_true', help='Resolve IP addresses to hostnames')
    parser.add_argument('--time-periods', '-t', nargs='+', choices=['30', '90', '180', '360', 'all'], 
                       default=['30', '90', '180', '360', 'all'], help='Time periods in days to include in report (default: 30 days and all time)')
    return parser.parse_args()


def main():
    """Main function to process DMARC reports."""
    args = parse_args()
    
    # Check if directory exists
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} is not a valid directory", file=sys.stderr)
        sys.exit(1)
    
    # Get list of potential report files
    file_patterns = ['*.xml', '*.xml.gz', '*.zip']
    report_files = []
    for pattern in file_patterns:
        report_files.extend(glob.glob(os.path.join(args.directory, pattern)))
    
    if not report_files:
        print(f"No DMARC report files found in {args.directory}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Found {len(report_files)} potential DMARC report files...")
    
    # Process each file
    reports = []
    for filepath in report_files:
        print(f"Processing {os.path.basename(filepath)}...", end="", flush=True)
        xml_content = extract_xml_from_file(filepath)
        if xml_content:
            report = parse_dmarc_report(xml_content)
            if report:
                # Ensure metadata and datetime objects exist for sorting
                if 'metadata' not in report:
                    report['metadata'] = {}
                if 'begin_date_dt' not in report['metadata']:
                    # Fallback if parsing failed to produce datetime, though it should
                    report['metadata']['begin_date_dt'] = datetime.min 
                reports.append(report)
                print(" OK")
            else:
                print(" Failed to parse")
        else:
            print(" Failed to extract XML")

    if not reports:
        print("No valid DMARC reports were successfully parsed.", file=sys.stderr)
        sys.exit(1)

    # Sort reports by their begin_date_dt
    reports.sort(key=lambda r: r['metadata'].get('begin_date_dt', datetime.min))
    
    # Parse time periods from command line args
    time_periods = args.time_periods
    
    # Analyze reports for specified time periods
    print(f"Analyzing {len(reports)} valid reports for time periods: {', '.join(time_periods)}...")
    stats = analyze_reports(reports, time_periods=time_periods)
    
    # Generate text report
    report_content = generate_report(stats, args.verbose, args.resolve_ips)
    
    # Output text report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report_content)
        print(f"Report written to {args.output}")
    else:
        if not args.html:  # Only print to stdout if not generating HTML
            print("\n" + report_content)
    
    # Generate HTML report if requested
    if args.html:
        html_report = generate_html_report(stats, args.resolve_ips)
        html_output = args.html_output or "dmarc_report.html"
        with open(html_output, 'w') as f:
            f.write(html_report)
        print(f"HTML report written to {html_output}")


if __name__ == "__main__":
    main()
