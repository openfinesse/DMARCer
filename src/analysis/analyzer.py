"""
DMARC Report Analysis

This module contains classes and functions for analyzing DMARC reports
and generating statistics and recommendations.
"""

from collections import defaultdict
from datetime import datetime, timedelta

from utils.helpers import TIME_PERIODS


def _calculate_stats_for_reports(reports_list):
    """
    Helper function to calculate DMARC statistics for a given list of reports.
    
    Args:
        reports_list: List of parsed DMARC reports
        
    Returns:
        dict: Statistics calculated from the reports
    """
    stats = {
        'total_messages': 0,
        'domains': set(),
        'domain_stats': defaultdict(lambda: {
            'count': 0,
            'dkim_pass': 0,
            'dkim_fail': 0,
            'spf_pass': 0,
            'spf_fail': 0,
            'fully_aligned': 0,
            'current_policy': 'none',
            'current_pct': 100,
            'current_sp': 'none',
            'sending_sources': set(),
            'policy_applied': defaultdict(int)
        }),
        'reporting_orgs': set(),
        'ips': defaultdict(lambda: {
            'count': 0,
            'domains': set(),
            'dkim_pass': 0,
            'dkim_fail': 0,
            'spf_pass': 0,
            'spf_fail': 0,
            'fully_aligned': 0,
            'disposition': defaultdict(int)
        }),
        'dkim_overall': {'pass': 0, 'fail': 0},
        'spf_overall': {'pass': 0, 'fail': 0},
        'disposition_overall': defaultdict(int),
        'failures_by_domain': defaultdict(int),
        'date_range': {'begin': None, 'end': None}
    }

    if not reports_list:  # Handle empty list of reports
        return stats

    for report in reports_list:
        if not report:
            continue
        
        metadata = report['metadata']
        policy = report['policy_published']
        records = report['records']
        
        # Track date range from datetime objects
        begin_date_dt = metadata.get('begin_date_dt')
        end_date_dt = metadata.get('end_date_dt')

        if begin_date_dt:
            if stats['date_range']['begin'] is None or begin_date_dt < stats['date_range']['begin']:
                stats['date_range']['begin'] = begin_date_dt
        if end_date_dt:
            if stats['date_range']['end'] is None or end_date_dt > stats['date_range']['end']:
                stats['date_range']['end'] = end_date_dt
        
        stats['reporting_orgs'].add(metadata.get('org_name', 'Unknown'))
        domain = policy.get('domain', 'Unknown')
        stats['domains'].add(domain)
        
        domain_stats = stats['domain_stats'][domain]
        domain_stats['current_policy'] = policy.get('policy', 'none')
        domain_stats['current_pct'] = int(policy.get('pct', '100'))
        # Ensure current_sp gets the most recent value from the reports for this period
        domain_stats['current_sp'] = policy.get('subpolicy', domain_stats['current_policy'])
        
        for record in records:
            msg_count = record.get('count', 0)
            stats['total_messages'] += msg_count
            
            source_ip = record.get('source_ip', 'Unknown')
            header_from = record.get('header_from', 'Unknown')
            dkim_result = record.get('dkim_result', 'unknown')
            spf_result = record.get('spf_result', 'unknown')
            disposition = record.get('disposition', 'unknown')
            
            if header_from == domain:
                domain_stats['count'] += msg_count
                domain_stats['sending_sources'].add(source_ip)
                domain_stats['policy_applied'][disposition] += msg_count
                
                if dkim_result.lower() == 'pass':
                    domain_stats['dkim_pass'] += msg_count
                else:
                    domain_stats['dkim_fail'] += msg_count
                
                if spf_result.lower() == 'pass':
                    domain_stats['spf_pass'] += msg_count
                else:
                    domain_stats['spf_fail'] += msg_count
                    
                if dkim_result.lower() == 'pass' or spf_result.lower() == 'pass':
                    domain_stats['fully_aligned'] += msg_count
            
            ip_stats = stats['ips'][source_ip]
            ip_stats['count'] += msg_count
            ip_stats['domains'].add(header_from)
            ip_stats['disposition'][disposition] += msg_count
            
            if dkim_result.lower() == 'pass':
                ip_stats['dkim_pass'] += msg_count
                stats['dkim_overall']['pass'] += msg_count
            else:
                ip_stats['dkim_fail'] += msg_count
                stats['dkim_overall']['fail'] += msg_count
                stats['failures_by_domain'][header_from] += msg_count
            
            if spf_result.lower() == 'pass':
                ip_stats['spf_pass'] += msg_count
                stats['spf_overall']['pass'] += msg_count
            else:
                ip_stats['spf_fail'] += msg_count
                stats['spf_overall']['fail'] += msg_count
                stats['failures_by_domain'][header_from] += msg_count
            
            if dkim_result.lower() == 'pass' or spf_result.lower() == 'pass':
                ip_stats['fully_aligned'] += msg_count
            
            stats['disposition_overall'][disposition] += msg_count
    
    return stats


def analyze_reports(all_sorted_reports, time_periods=None):
    """
    Analyze DMARC reports and generate aggregate statistics for specified time periods.
    
    Args:
        all_sorted_reports: List of parsed DMARC reports, sorted by date
        time_periods: List of time periods to analyze (e.g., ['30', '90', 'all'])
    
    Returns:
        Dictionary with stats for each time period and a flag indicating which periods have meaningful data
    """
    if time_periods is None:
        time_periods = ['30', 'all']
        
    if not all_sorted_reports:
        # If no reports, return empty stats for all requested periods
        empty_stats = _calculate_stats_for_reports([])
        stats_bundle = {'periods': {}}
        for period in time_periods:
            stats_bundle['periods'][period] = {
                'stats': empty_stats,
                'is_meaningful': False
            }
        return stats_bundle

    # Find the latest date across all reports to anchor time period calculations
    max_end_date = None
    for r in all_sorted_reports:
        report_end_date = r.get('metadata', {}).get('end_date_dt')
        if report_end_date:
            if max_end_date is None or report_end_date > max_end_date:
                max_end_date = report_end_date

    # If we couldn't determine a max date, use current datetime as fallback
    if max_end_date is None:
        max_end_date = datetime.now()

    # Calculate statistics for all requested time periods
    stats_bundle = {'periods': {}}
    
    for period_key in time_periods:
        days = TIME_PERIODS[period_key]
        
        # For 'all' time period, use all reports
        if period_key == 'all':
            period_stats = _calculate_stats_for_reports(all_sorted_reports)
            stats_bundle['periods']['all'] = {
                'stats': period_stats,
                'is_meaningful': period_stats['total_messages'] > 0,
                'days': None  # Represents all time
            }
            continue
        
        # For specific day-based periods, filter reports within the time window
        period_start = max_end_date - timedelta(days=days)
        filtered_reports = []
        
        for r in all_sorted_reports:
            report_end_date = r.get('metadata', {}).get('end_date_dt')
            if report_end_date and report_end_date >= period_start:
                filtered_reports.append(r)
        
        period_stats = _calculate_stats_for_reports(filtered_reports)
        
        # A period is considered meaningful if it has at least 1 report with messages
        is_meaningful = len(filtered_reports) > 0 and period_stats['total_messages'] > 0
        
        stats_bundle['periods'][period_key] = {
            'stats': period_stats,
            'is_meaningful': is_meaningful,
            'days': days
        }
    
    # Set a default period for primary display based on meaningful data availability
    # Prefer 30 days if available, otherwise use the smallest meaningful period
    default_period = None
    if 'periods' in stats_bundle:
        if '30' in stats_bundle['periods'] and stats_bundle['periods']['30']['is_meaningful']:
            default_period = '30'
        else:
            # Find the smallest meaningful period
            for period in sorted(stats_bundle['periods'].keys(), 
                                key=lambda x: 9999 if x == 'all' else int(x)):
                if stats_bundle['periods'][period]['is_meaningful']:
                    default_period = period
                    break
            
            # If no meaningful periods found, default to 'all'
            if default_period is None and 'all' in stats_bundle['periods']:
                default_period = 'all'
    
    stats_bundle['default_period'] = default_period
    return stats_bundle


def generate_policy_recommendations(stats_bundle, period_key=None):
    """
    Generate DMARC policy recommendations based on authentication statistics for a specific period.
    
    Args:
        stats_bundle: Dictionary with statistics for different time periods
        period_key: Key of the time period to use for generating recommendations
    
    Returns:
        list: List of policy recommendations for each domain
    """
    # If no specific period is provided, use the default period
    if period_key is None:
        period_key = stats_bundle.get('default_period', 'all')
    
    # Ensure the requested period exists
    if period_key not in stats_bundle.get('periods', {}):
        period_key = 'all'  # Fallback to all time if requested period doesn't exist
    
    period_data = stats_bundle['periods'][period_key]
    stats = period_data['stats']
    days = period_data.get('days')
    
    recommendations = []
    
    # Check each domain separately
    for domain, domain_stats in stats['domain_stats'].items():
        domain_recs = []
        
        if domain_stats['count'] == 0:
            period_desc = f"the last {days} days" if days else "the entire analyzed period"
            domain_recs.append(f"No data available for direct messages from {domain} in {period_desc}.")
            # Add to recommendations but skip detailed analysis
            recommendations.append({
                'domain': domain,
                'recommendations': domain_recs,
                'stats': domain_stats
            })
            continue
            
        # Calculate authentication rates
        dkim_pass_rate = domain_stats['dkim_pass'] / domain_stats['count'] if domain_stats['count'] > 0 else 0
        spf_pass_rate = domain_stats['spf_pass'] / domain_stats['count'] if domain_stats['count'] > 0 else 0
        alignment_rate = domain_stats['fully_aligned'] / domain_stats['count'] if domain_stats['count'] > 0 else 0
        
        current_policy = domain_stats['current_policy']
        current_pct = domain_stats['current_pct']
        current_sp = domain_stats.get('current_sp', current_policy) # .get because current_sp might not be in older structure

        # Add a note about which period's data is being used
        if days:
            period_desc = f"the last {days} days"
        else:
            # For 'all' period, try to provide date range if available
            if stats['date_range']['begin'] and stats['date_range']['end']:
                begin_date = stats['date_range']['begin'].strftime('%Y-%m-%d')
                end_date = stats['date_range']['end'].strftime('%Y-%m-%d')
                period_desc = f"all available data ({begin_date} to {end_date})"
            else:
                period_desc = "all available data"
                
        domain_recs.append(f"INFO: Recommendations based on {period_desc}.")
        
        # --- Policy progression recommendations ---
        if current_policy == 'none':
            if alignment_rate >= 0.95:
                domain_recs.append(f"POLICY UPGRADE: Consider moving to 'p=quarantine' with pct=5 as alignment rate is excellent ({alignment_rate:.1%}).")
            elif alignment_rate >= 0.85:
                domain_recs.append(f"MONITOR: Continue with 'p=none' but work toward 'p=quarantine' as alignment rate is good ({alignment_rate:.1%}).")
            else:
                domain_recs.append(f"CAUTION: Maintain 'p=none' while improving alignment rate (currently {alignment_rate:.1%}).")
                domain_recs.append(f"IMPROVEMENT NEEDED: Address authentication issues before considering enforcement policies.")
        elif current_policy == 'quarantine':
            if alignment_rate >= 0.98:
                if current_pct < 100:
                    domain_recs.append(f"PERCENTAGE INCREASE: Increase pct value from {current_pct}% to {min(current_pct + 25, 100)}% as alignment is excellent.")
                else:
                    domain_recs.append(f"POLICY UPGRADE: Consider moving to 'p=reject' with pct=5 as alignment rate is excellent ({alignment_rate:.1%}).")
            elif alignment_rate >= 0.9:
                if current_pct < 100:
                    domain_recs.append(f"PERCENTAGE INCREASE: Consider increasing pct value from {current_pct}% to {min(current_pct + 10, 100)}%.")
                else:
                    domain_recs.append(f"MAINTAIN: Keep 'p=quarantine' at 100% while monitoring for any issues.")
            else:
                if current_pct > 25:
                    domain_recs.append(f"CAUTION: Consider decreasing pct value to reduce potential legitimate email loss.")
                domain_recs.append(f"IMPROVEMENT NEEDED: Work on authentication issues before increasing enforcement.")
        elif current_policy == 'reject':
            if current_pct < 100:
                if alignment_rate >= 0.98:
                    domain_recs.append(f"PERCENTAGE INCREASE: Consider increasing pct value from {current_pct}% to {min(current_pct + 20, 100)}%.")
                elif alignment_rate >= 0.95:
                    domain_recs.append(f"PERCENTAGE INCREASE: Consider a modest increase from {current_pct}% to {min(current_pct + 10, 100)}%.")
                else:
                    domain_recs.append(f"CAUTION: Maintain current pct={current_pct}% until alignment improves ({alignment_rate:.1%}).")
            else:
                domain_recs.append(f"OPTIMAL: DMARC policy is at maximum enforcement (p=reject, pct=100).")
                if alignment_rate < 0.98:
                    domain_recs.append(f"MONITOR: Watch for legitimate email loss with current strict policy.")
        
        # --- Specific authentication recommendations ---
        if dkim_pass_rate < 0.9:
            domain_recs.append(f"DKIM ISSUE: Improve DKIM signing (currently {dkim_pass_rate:.1%} pass rate).")
            if dkim_pass_rate < 0.7:
                domain_recs.append(f"CRITICAL: DKIM failures are significant and require immediate attention.")
        if spf_pass_rate < 0.9:
            domain_recs.append(f"SPF ISSUE: Improve SPF alignment (currently {spf_pass_rate:.1%} pass rate).")
            if spf_pass_rate < 0.7:
                domain_recs.append(f"CRITICAL: SPF failures are significant and require immediate attention.")
        if current_sp != 'reject' and current_policy != 'none':
            domain_recs.append(f"SUBDOMAIN POLICY: Consider setting 'sp=reject' to protect against subdomain spoofing.")
        
        num_sources = len(domain_stats['sending_sources'])
        if num_sources > 10 and current_policy != 'none' and current_pct > 50:
            domain_recs.append(f"DIVERSITY WARNING: You have {num_sources} sending sources, which increases risk during policy enforcement.")

        recommendations.append({
            'domain': domain,
            'recommendations': domain_recs,
            'stats': {
                'messages': domain_stats['count'],
                'dkim_rate': dkim_pass_rate * 100,
                'spf_rate': spf_pass_rate * 100,
                'alignment_rate': alignment_rate * 100,
                'current_policy': current_policy,
                'current_pct': current_pct,
                'current_sp': current_sp,
                'num_sources': num_sources,
                'policy_results': dict(domain_stats['policy_applied'])
            }
        })
    
    return recommendations
