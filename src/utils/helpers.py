"""
Utility functions for the DMARC Analyzer.

This module contains various helper functions used across the DMARC analyzer.
"""

import socket
import html
from collections import defaultdict

# Default time periods in days
TIME_PERIODS = {
    '30': 30,
    '90': 90,
    '180': 180,
    '360': 360,
    'all': None  # None represents all data
}

# Mapping of common patterns to source organizations
ORG_PATTERNS = {
    'google': 'Google',
    'gmail': 'Google',
    'googlemail': 'Google',
    'amazon': 'Amazon',
    'aws': 'Amazon AWS',
    'microsoft': 'Microsoft',
    'outlook': 'Microsoft',
    'office365': 'Microsoft Office 365',
    'sendgrid': 'SendGrid',
    'mailchimp': 'Mailchimp',
    'sparkpost': 'SparkPost',
    'postmark': 'Postmark',
    'mailgun': 'Mailgun',
    'yandex': 'Yandex',
    'yahoo': 'Yahoo',
    'aol': 'AOL',
    'protonmail': 'ProtonMail',
    'zoho': 'Zoho',
    'fastmail': 'Fastmail',
    'comcast': 'Comcast',
    'verizon': 'Verizon',
    'att': 'AT&T',
    'cloudflare': 'Cloudflare',
    'nationbuilder': 'NationBuilder',
    'nb-mail': 'NationBuilder',  # NationBuilder email servers might use this format
    'nationsend': 'NationBuilder',  # Common NationBuilder email sending domain
    'nationbuilder.com': 'NationBuilder',
}

# Map provider patterns to their main domains for favicon retrieval
PROVIDER_DOMAINS = {
    'google': "google.com",
    'gmail': "gmail.com",
    'googlemail': "googlemail.com",
    'outlook': "outlook.com",
    'microsoft': "microsoft.com",
    'office365': "office365.com",
    'yahoo': "yahoo.com",
    'postmark': "postmarkapp.com",
    'amazon': "amazon.com",
    'aws': "aws.amazon.com",
    'sendgrid': "sendgrid.com",
    'mailchimp': "mailchimp.com",
    'yandex': "yandex.com",
    'zoho': "zoho.com",
    'cloudflare': "cloudflare.com",
    'nationbuilder': "nationbuilder.com",
}

# Service provider icons mapping for visual identification
PROVIDER_ICONS = {
    'google': "&#128309;",  # Blue circle for Google
    'gmail': "&#128309;",
    'googlemail': "&#128309;",
    'outlook': "&#128995;",  # Purple square for Outlook/Microsoft
    'microsoft': "&#128995;",
    'office365': "&#128995;",
    'yahoo': "&#128997;",  # Purple circle for Yahoo
    'postmark': "&#9888;&#65039;",  # Warning triangle for Postmark
    'amazon': "&#128992;",  # Yellow square for Amazon
    'aws': "&#128992;",
    'sendgrid': "&#128994;",  # Green square for SendGrid
    'mailchimp': "&#129418;",  # Monkey emoji for Mailchimp
    'nationbuilder': "&#128736;",  # Wrench emoji for NationBuilder
    'unknown': "&#9679;",  # Default black circle
}


def resolve_ip(ip):
    """Resolve an IP address to a hostname using reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def group_ips_by_source(ips_stats, resolve=False):
    """Group IP addresses by their source organization based on reverse DNS lookups."""
    ip_groups = defaultdict(lambda: {
        'ips': [],
        'count': 0,
        'domains': set(),
        'dkim_pass': 0,
        'dkim_fail': 0,
        'spf_pass': 0,
        'spf_fail': 0,
        'fully_aligned': 0,
        'dispositions': defaultdict(int)
    })
    
    for ip, stats in ips_stats.items():
        hostname = None
        if resolve:
            hostname = resolve_ip(ip)
        
        # Determine the organization
        org_name = "Unknown"
        hostname_domain = None
        
        if hostname:
            # Extract domain from hostname for potential favicon use
            parts = hostname.split('.')
            if len(parts) >= 2:
                hostname_domain = f"{parts[-2]}.{parts[-1]}"
            
            # Check if hostname matches any known patterns
            hostname_lower = hostname.lower()
            for pattern, name in ORG_PATTERNS.items():
                if pattern in hostname_lower:
                    org_name = name
                    break
            
            # If still unknown, use a simplified domain from hostname
            if org_name == "Unknown" and len(parts) >= 2:
                org_name = parts[-2].capitalize()  # Use the second-level domain
        
        # Add IP to the appropriate group
        ip_groups[org_name]['ips'].append(ip)
        ip_groups[org_name]['count'] += stats['count']
        ip_groups[org_name]['domains'].update(stats['domains'])
        ip_groups[org_name]['dkim_pass'] += stats['dkim_pass']
        ip_groups[org_name]['dkim_fail'] += stats['dkim_fail']
        ip_groups[org_name]['spf_pass'] += stats['spf_pass']
        ip_groups[org_name]['spf_fail'] += stats['spf_fail']
        ip_groups[org_name]['fully_aligned'] += stats['fully_aligned']
        
        # Update dispositions
        for disp, count in stats['disposition'].items():
            ip_groups[org_name]['dispositions'][disp] += count
    
    return ip_groups


def get_favicon_url(domain):
    """Generate a favicon URL for a domain."""
    return f"https://icons.duckduckgo.com/ip3/{html.escape(domain)}.ico"
