"""
Text Report Generator for DMARC Analyzer

This module generates a human-readable text report from DMARC analysis results.
"""

from tabulate import tabulate

from utils.helpers import group_ips_by_source, resolve_ip
from analysis.analyzer import generate_policy_recommendations


def generate_report(stats, verbose=False, resolve_ips=False):
    """
    Generate a human-readable report from the analyzed statistics.
    
    Args:
        stats: Dictionary with analyzed DMARC statistics
        verbose: Whether to include detailed IP information
        resolve_ips: Whether to resolve IP addresses to hostnames
        
    Returns:
        str: Formatted text report
    """
    # Decide which stats to use for the report
    stats_bundle = stats  # stats is now the bundle
    display_stats = stats_bundle['periods'][stats_bundle['default_period']]['stats']
    report_period_info = f" (Recent Period)" if stats_bundle['periods'][stats_bundle['default_period']]['is_meaningful'] else " (Overall Period)"

    if not display_stats['total_messages']:
        return "No valid DMARC reports found or no messages reported for the analyzed period."
    
    report_lines = []
    
    # Summary section
    report_lines.append("= DMARC Report Summary" + report_period_info + " =")
    report_lines.append(f"Total Messages: {display_stats['total_messages']}")
    report_lines.append(f"Domains Protected: {', '.join(sorted(display_stats['domains']))}")
    report_lines.append(f"Reporting Organizations: {', '.join(sorted(display_stats['reporting_orgs']))}")
    report_lines.append("")
    
    # Authentication Summary
    report_lines.append("= Authentication Summary" + report_period_info + " =")
    dkim_pass = display_stats['dkim_overall']['pass']
    dkim_fail = display_stats['dkim_overall']['fail']
    dkim_total = dkim_pass + dkim_fail
    dkim_pass_pct = (dkim_pass / dkim_total) * 100 if dkim_total else 0
    
    spf_pass = display_stats['spf_overall']['pass']
    spf_fail = display_stats['spf_overall']['fail']
    spf_total = spf_pass + spf_fail
    spf_pass_pct = (spf_pass / spf_total) * 100 if spf_total else 0
    
    report_lines.append(f"DKIM: {dkim_pass}/{dkim_total} passed ({dkim_pass_pct:.1f}%)")
    report_lines.append(f"SPF: {spf_pass}/{spf_total} passed ({spf_pass_pct:.1f}%)")
    report_lines.append("")
    
    # Disposition Summary
    report_lines.append("= Policy Enforcement" + report_period_info + " =")
    disposition_table = []
    for disposition, count in sorted(display_stats['disposition_overall'].items(), key=lambda x: x[1], reverse=True):
        pct = (count / display_stats['total_messages']) * 100
        disposition_table.append([disposition, count, f"{pct:.1f}%"])
    report_lines.append(tabulate(disposition_table, headers=["Disposition", "Count", "%"], tablefmt="simple"))
    report_lines.append("")
    
    # Group IPs by source and display their domains
    report_lines.append("= IP Sources Grouped by Organization" + report_period_info + " =")
    ip_groups = group_ips_by_source(display_stats['ips'], resolve=resolve_ips)
    
    group_table = []
    for org_name, group_stats in sorted(ip_groups.items(), key=lambda x: x[1]['count'], reverse=True):
        num_ips = len(group_stats['ips'])
        domains_str = ', '.join(sorted(group_stats['domains']))
        
        dkim_pass_pct = (group_stats['dkim_pass'] / group_stats['count']) * 100 if group_stats['count'] else 0
        spf_pass_pct = (group_stats['spf_pass'] / group_stats['count']) * 100 if group_stats['count'] else 0
        aligned_pct = (group_stats['fully_aligned'] / group_stats['count']) * 100 if group_stats['count'] else 0
        
        group_table.append([
            org_name,
            num_ips,
            group_stats['count'],
            f"{dkim_pass_pct:.1f}%",
            f"{spf_pass_pct:.1f}%",
            f"{aligned_pct:.1f}%",
            domains_str[:50] + ('...' if len(domains_str) > 50 else '')
        ])
    
    report_lines.append(tabulate(group_table, 
                                headers=["Source", "IPs", "Messages", "DKIM Pass", "SPF Pass", "Aligned", "Domains"], 
                                tablefmt="simple"))
    report_lines.append("")
    
    # Top IP sources
    report_lines.append("= Top IP Sources" + report_period_info + " =")
    ip_table = []
    for ip, ip_stats in sorted(display_stats['ips'].items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
        dkim_pass_pct = (ip_stats['dkim_pass'] / ip_stats['count']) * 100 if ip_stats['count'] else 0
        spf_pass_pct = (ip_stats['spf_pass'] / ip_stats['count']) * 100 if ip_stats['count'] else 0
        fully_aligned_pct = (ip_stats['fully_aligned'] / ip_stats['count']) * 100 if ip_stats['count'] else 0
        
        # Add hostname if resolved
        ip_display = ip
        if resolve_ips:
            hostname = resolve_ip(ip)
            if hostname:
                ip_display = f"{ip} ({hostname})"
        
        domains = ', '.join(sorted(ip_stats['domains']))
        ip_table.append([
            ip_display, 
            ip_stats['count'],
            f"{dkim_pass_pct:.1f}%", 
            f"{spf_pass_pct:.1f}%", 
            f"{fully_aligned_pct:.1f}%",
            domains
        ])
    report_lines.append(tabulate(ip_table, headers=["IP", "Messages", "DKIM Pass", "SPF Pass", "Aligned", "Domains"], tablefmt="simple"))
    report_lines.append("")
    
    # Failures by domain
    if display_stats['failures_by_domain']:
        report_lines.append("= Authentication Failures by Domain" + report_period_info + " =")
        failures_table = []
        for domain, count in sorted(display_stats['failures_by_domain'].items(), key=lambda x: x[1], reverse=True):
            failures_table.append([domain, count])
        report_lines.append(tabulate(failures_table, headers=["Domain", "Failures"], tablefmt="simple"))
        report_lines.append("")
    
    # DMARC Policy Recommendations
    report_lines.append("= DMARC Policy Recommendations =")  # Recommendations already use recent stats
    policy_recommendations = generate_policy_recommendations(stats_bundle)  # Pass the whole bundle
    
    for policy_rec in policy_recommendations:
        domain = policy_rec['domain']
        domain_stats = policy_rec['stats']
        
        report_lines.append(f"\nDomain: {domain}")
        report_lines.append(f"Current DMARC Policy: p={domain_stats['current_policy']}, pct={domain_stats['current_pct']}%, sp={domain_stats['current_sp']}")
        report_lines.append(f"Messages: {domain_stats['messages']} from {domain_stats['num_sources']} source IPs")
        report_lines.append(f"Authentication Rates: DKIM {domain_stats['dkim_rate']:.1f}%, SPF {domain_stats['spf_rate']:.1f}%, Aligned {domain_stats['alignment_rate']:.1f}%")
        
        # Policy results table
        if domain_stats['policy_results']:
            policy_table = []
            for disp, count in domain_stats['policy_results'].items():
                pct = (count / domain_stats['messages']) * 100 if domain_stats['messages'] > 0 else 0
                policy_table.append([disp, count, f"{pct:.1f}%"])
            report_lines.append("Policy Application Results:")
            report_lines.append(tabulate(policy_table, headers=["Disposition", "Count", "%"], tablefmt="simple"))
        
        report_lines.append("Recommendations:")
        if policy_rec['recommendations']:
            for rec in policy_rec['recommendations']:
                report_lines.append(f"  - {rec}")
        else:
            report_lines.append("  - No specific recommendations.")
    
    # DMARC Policy Reference Guide
    report_lines.append("\n= DMARC Policy Reference Guide =")
    report_lines.append("Policy Values (p=):")
    report_lines.append("  none - Monitor only, take no action on failures (monitoring mode)")
    report_lines.append("  quarantine - Mark or junk messages that fail authentication")
    report_lines.append("  reject - Block messages that fail authentication")
    
    report_lines.append("\nPercentage (pct=):")
    report_lines.append("  Controls what percentage of messages are subject to filtering")
    report_lines.append("  Start low (5-10%) and gradually increase as confidence grows")
    
    report_lines.append("\nSubdomain Policy (sp=):")
    report_lines.append("  Controls policy for subdomains (e.g., mail from sub.example.com when domain is example.com)")
    report_lines.append("  Often set to 'reject' to prevent subdomain spoofing")
    
    report_lines.append("\nDMARC Policy Progression Path:")
    report_lines.append("  1. p=none with RUA/RUF reporting enabled")
    report_lines.append("  2. p=quarantine with low pct value (5-25%)")
    report_lines.append("  3. Gradually increase pct value to 100%")
    report_lines.append("  4. p=reject with low pct value (5-25%)")
    report_lines.append("  5. Gradually increase pct value to 100%")
    
    # General recommendations
    report_lines.append("\n= General DMARC Implementation Tips =")
    if dkim_pass_pct < 90 or spf_pass_pct < 90:
        report_lines.append("- Fix authentication issues before increasing enforcement levels")
    report_lines.append("- Implement proper SPF, DKIM and DMARC for all domains, even non-sending domains")
    report_lines.append("- Monitor reports regularly and adjust policies based on findings")
    report_lines.append("- Coordinate with third-party senders to ensure they authenticate properly")
    report_lines.append("- Consider using multiple DKIM selectors for different mail streams")
    report_lines.append("- Implement a process to respond to authentication failures quickly")
    
    # If verbose, include more detailed IP information
    if verbose:
        report_lines.append("")
        report_lines.append("= Detailed IP Information" + report_period_info + " =")
        for ip, ip_stats in sorted(display_stats['ips'].items(), key=lambda x: x[1]['count'], reverse=True):
            # Add hostname if resolved
            ip_display = ip
            if resolve_ips:
                hostname = resolve_ip(ip)
                if hostname:
                    ip_display = f"{ip} ({hostname})"
                    
            report_lines.append(f"\nIP: {ip_display}")
            report_lines.append(f"Message Count: {ip_stats['count']}")
            report_lines.append(f"Domains: {', '.join(sorted(ip_stats['domains']))}")
            report_lines.append(f"DKIM: {ip_stats['dkim_pass']} pass, {ip_stats['dkim_fail']} fail")
            report_lines.append(f"SPF: {ip_stats['spf_pass']} pass, {ip_stats['spf_fail']} fail")
            report_lines.append(f"Fully Aligned: {ip_stats['fully_aligned']}")
            report_lines.append("Dispositions:")
            for disp, count in ip_stats['disposition'].items():
                report_lines.append(f"  - {disp}: {count}")
    
    return "\n".join(report_lines)
