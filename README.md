# DMARC Analyzer

A tool that enables easy analysis of DMARC XML reports and provides insights into SPF and DKIM alignment.
See where your emails are coming from and how they are being authenticated.

This project was heavily inspired by [Postmark's DMARC Monitoring Email](https://dmarc.postmarkapp.com/).

## Installation

```bash
pip install .
```

Recommended to use a virtual environment.

## Usage

```bash
dmarc-analyzer /path/to/dmarc/reports
```

### Options

- `--output`, `-o`: Output file (default: stdout)
- `--verbose`, `-v`: Verbose output
- `--html`: Generate HTML report
- `--html-output`: HTML output file (default: dmarc_report.html)
- `--resolve-ips`, `-r`: Resolve IP addresses to hostnames
- `--time-periods`, `-t`: Time periods in days to include in report (choices: 30, 90, 180, 360, all) 