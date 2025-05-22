"""
HTML Report Generator for DMARC Analyzer

This module generates an HTML report with visualizations from DMARC analysis results.
"""

import html
from datetime import datetime

from utils.helpers import group_ips_by_source, resolve_ip, get_favicon_url, PROVIDER_ICONS, PROVIDER_DOMAINS
from analysis.analyzer import generate_policy_recommendations


def source_icon_html(source):
    """Generate the HTML for a source icon."""
    # If a favicon is already set, use it
    if source["favicon"]:
        return f'<img src="{source["favicon"]}" class="favicon" alt="" onerror="this.style.display=\'none\';" />'
    
    # If no favicon but we have a name, try to generate one from the name
    elif "name" in source and source["name"] != "Unknown":
        # Try to extract a domain from the source name for unknown providers
        name_parts = source["name"].lower().split()
        if name_parts:
            potential_domain = name_parts[0].strip(".,;:!?")
            # Only add .com if it doesn't already have a TLD
            if "." not in potential_domain:
                potential_domain += ".com"  # Assume .com TLD if no domain extension
            # Use Google favicon service
            return f'<img src="{get_favicon_url(potential_domain)}" class="favicon" alt="" onerror="this.style.display=\'none\';" />'
    
    # Fallback to the emoji icon
    return source["icon"]


def generate_source_section(title, description, sources):
    """Generate HTML for a sources section."""
    if not sources:
        return f"""
        <div class="section">
            <h2>{title}</h2>
            <p>{description}</p>
            <p>No sources found in this category.</p>
        </div>
        """
    
    html_content = f"""
    <div class="section">
        <h2>{title}</h2>
        <p>{description}</p>
    """
    
    # Generate HTML for each source
    for source in sources:
        html_content += f"""
        <div class="source">
            <div class="source-header">
                <span class="icon">
                    {source_icon_html(source)}
                </span>
                <span class="name">{source['name']}</span>
                <span class="stats">
                    <span class="stat-item">TOTAL</span>
                    <span class="stat-value">{source['total']}</span>
                    <span class="stat-item">PASSED SPF</span>
                    <span class="stat-value">{source['spf_pass']}</span>
                    <span class="stat-item">PASSED DKIM</span>
                    <span class="stat-value">{source['dkim_pass']}</span>
                </span>
            </div>
        """
        
        # Add IPs for this source
        for ip_entry in source['ips']:
            html_content += f"""
            <div class="ip-row">
                <span class="ip">{ip_entry['ip']}</span>
                <span class="stats">
                    <span class="stat-placeholder"></span><span class="stat-value">{ip_entry['count']}</span>
                    <span class="stat-placeholder"></span><span class="stat-value">{ip_entry['spf_pass']}</span>
                    <span class="stat-placeholder"></span><span class="stat-value">{ip_entry['dkim_pass']}</span>
                </span>
            </div>
            """
        
        html_content += """
        </div>
        """
    
    # Add helper links for specific sections
    if title == "Other sources":
        html_content += """
        <ul class="help-links">
            <li>For SPF: Configure TXT records with authorized senders</li>
            <li>For DKIM: Set up signing keys for all sending services</li>
        </ul>
        """
    elif title == "Forwarded email sources":
        html_content += """
        <p>Email forwarding typically preserves DKIM headers but originates from new IP addresses not in your SPF record.</p>
        """
    
    html_content += """
    </div>
    """
    return html_content


def generate_period_content(period_key, stats_bundle):
    """Generate HTML content for a specific time period."""
    period_data = stats_bundle['periods'][period_key]
    display_stats = period_data['stats']
    days = period_data.get('days')
    
    # Calculate summary stats for this period
    total_messages = display_stats['total_messages']
    dkim_pass = display_stats['dkim_overall']['pass']
    dkim_fail = display_stats['dkim_overall']['fail']
    spf_pass = display_stats['spf_overall']['pass']
    spf_fail = display_stats['spf_overall']['fail']
    
    # Count emails that passed either SPF or DKIM
    passed_either = 0
    failed_both = 0
    
    for ip, ip_stats in display_stats['ips'].items():
        passed_either += ip_stats['fully_aligned']  # Messages that passed DMARC
        failed_both += ip_stats['count'] - ip_stats['fully_aligned']  # Messages that failed DMARC
    
    # Get the primary domain (first in sorted list)
    domain_name = sorted(display_stats['domains'])[0] if display_stats['domains'] else "Domain"
    
    # Format date range from the DMARC reports
    if display_stats['date_range']['begin'] and display_stats['date_range']['end']:
        begin_date = display_stats['date_range']['begin']
        end_date = display_stats['date_range']['end']
        
        # Format like "May 15 - May 22"
        if begin_date.month == end_date.month:
            date_range = f"{begin_date.strftime('%b')} {begin_date.day} - {end_date.day}"
        else:
            date_range = f"{begin_date.strftime('%b')} {begin_date.day} - {end_date.strftime('%b')} {end_date.day}"
    else:
        # Fallback to current date if no date range found
        date_range = datetime.now().strftime("%b %d - %b %d")  # e.g., "May 15 - May 22"
    
    # Group IPs by source
    ip_groups = group_ips_by_source(display_stats['ips'], resolve=True)
    
    # Process and categorize sources
    verified_sources = []
    other_sources = []
    forwarded_sources = []
    
    # First group IPs by their organizations
    for org_name, group_stats in sorted(ip_groups.items(), key=lambda x: x[1]['count'], reverse=True):
        # Calculate rates
        dkim_pass_pct = int((group_stats['dkim_pass'] / group_stats['count']) * 100) if group_stats['count'] else 0
        spf_pass_pct = int((group_stats['spf_pass'] / group_stats['count']) * 100) if group_stats['count'] else 0
        
        # Determine icon for this organization
        icon = PROVIDER_ICONS.get('unknown')
        favicon = None
        
        # First try to match known providers
        for pattern, domain in PROVIDER_DOMAINS.items():
            if pattern.lower() in org_name.lower():
                # Set icon based on pattern if available
                if pattern in PROVIDER_ICONS:
                    icon = PROVIDER_ICONS[pattern]
                # Get favicon for this pattern
                favicon = get_favicon_url(domain)
                break
        
        # If no favicon yet, try to extract domain from org name
        if not favicon and org_name != "Unknown":
            # Clean up org name and try to extract a domain
            domain_candidate = org_name.lower().split()[0].strip(".,;:!?")
            if "." not in domain_candidate and len(domain_candidate) > 2:  # Avoid single/double letter domains
                domain_candidate += ".com"  # Assume .com TLD for common names
            
            if "." in domain_candidate:  # Only use if it looks like a domain
                favicon = get_favicon_url(domain_candidate)
        
        # Create source entry with all IPs
        source_entry = {
            'name': html.escape(org_name),
            'icon': icon,
            'favicon': favicon,
            'total': group_stats['count'],
            'dkim_pass': f"{dkim_pass_pct}%",
            'spf_pass': f"{spf_pass_pct}%",
            'ips': []
        }
        
        # Add individual IPs
        for ip in group_stats['ips']:
            ip_stats = display_stats['ips'][ip]
            ip_dkim_pct = int((ip_stats['dkim_pass'] / ip_stats['count']) * 100) if ip_stats['count'] else 0
            ip_spf_pct = int((ip_stats['spf_pass'] / ip_stats['count']) * 100) if ip_stats['count'] else 0
            
            source_entry['ips'].append({
                'ip': html.escape(ip),
                'count': ip_stats['count'],
                'dkim_pass': f"{ip_dkim_pct}%",
                'spf_pass': f"{ip_spf_pct}%"
            })
        
        # Categorize based on authentication results
        if dkim_pass_pct >= 90 or spf_pass_pct >= 90:
            verified_sources.append(source_entry)
        elif dkim_pass_pct >= 80 and spf_pass_pct <= 20:
            forwarded_sources.append(source_entry)
        else:
            other_sources.append(source_entry)
    
    # Generate recommendations specific to this period
    recommendations_html = ""
    all_recommendations = set()
    policy_recommendations = generate_policy_recommendations(stats_bundle, period_key)
    
    for policy_rec in policy_recommendations:
        for rec in policy_rec['recommendations']:
            if rec.startswith("INFO:"):
                continue  # Skip the INFO prefix recommendations
            if not rec.startswith("CRITICAL") and not rec.startswith("CAUTION"):
                all_recommendations.add(rec.split(": ", 1)[1] if ": " in rec else rec)
    
    if not all_recommendations:
        all_recommendations = ["Set up SPF and DKIM for all sending sources.",
                              "Configure a DMARC policy for better email deliverability."]
    
    for rec in all_recommendations:
        recommendations_html += f"<li>{html.escape(rec)}</li>"
    
    # Map period keys to display names
    period_display_names = {
        '30': 'Last 30 Days',
        '90': 'Last 90 Days',
        '180': 'Last 180 Days',
        '360': 'Last Year',
        'all': 'All Time'
    }
    
    # Generate HTML for this period
    period_html = f'''
    <div class="summary-box">
        <div class="summary-item">
            <span class="summary-number neutral">{total_messages}</span>
            <div>Emails processed</div>
        </div>
        <div class="summary-item">
            <span class="summary-number success">{passed_either}</span>
            <div>Emails passed DMARC</div>
        </div>
        <div class="summary-item">
            <span class="summary-number failure">{failed_both}</span>
            <div>Emails failed DMARC</div>
        </div>
    </div>
    
    {generate_source_section(
        "Authenticated sources",
        "These are sources that were identified as legitimate senders for your domain based on authentication results.",
        verified_sources
    )}
    
    {generate_source_section(
        "Unauthenticated sources",
        "These sources are sending emails from your domain, but could not be verified through authentication.",
        other_sources
    )}
    
    {generate_source_section(
        "Forwarded email sources",
        "These sources appear to be forwarded emails. Forwarded emails often preserve DKIM signatures while failing SPF alignment.",
        forwarded_sources
    )}
    
    <div class="section recommendations">
        <h2>Recommendations for {period_display_names.get(period_key, period_key)}</h2>
        <ul>
            {recommendations_html}
        </ul>
    </div>
    '''
    return period_html, date_range, html.escape(domain_name)


def generate_html_report(stats, resolve_ips=False):
    """
    Generate an HTML report with visualizations from DMARC analysis results.
    
    Args:
        stats: Dictionary with analyzed DMARC statistics
        resolve_ips: Whether to resolve IP addresses to hostnames (not used directly in this implementation)
        
    Returns:
        str: Formatted HTML report
    """
    stats_bundle = stats  # stats is now the bundle
    
    # Get available periods
    available_periods = list(stats_bundle.get('periods', {}).keys())
    default_period = stats_bundle.get('default_period', 'all')
    
    # Map period keys to display names
    period_display_names = {
        '30': 'Last 30 Days',
        '90': 'Last 90 Days',
        '180': 'Last 180 Days',
        '360': 'Last Year',
        'all': 'All Time'
    }
    
    # Only include periods that have data
    meaningful_periods = []
    for period in available_periods:
        if stats_bundle['periods'][period]['is_meaningful'] or period == 'all':
            meaningful_periods.append(period)
    
    # If no meaningful periods, ensure 'all' is included
    if not meaningful_periods and 'all' in available_periods:
        meaningful_periods = ['all']
    elif not meaningful_periods:
        meaningful_periods = available_periods[:1]  # Use first available period
    
    # Ensure default_period is in meaningful_periods
    if default_period not in meaningful_periods:
        default_period = meaningful_periods[0] if meaningful_periods else 'all'
    
    # Generate content for all periods
    period_contents = {}
    main_date_range = ""
    main_domain_name = ""
    date_ranges = {}  # Store date ranges for each period
    
    for period in meaningful_periods:
        period_html, date_range, domain_name = generate_period_content(period, stats_bundle)
        period_contents[period] = period_html
        date_ranges[period] = date_range  # Store the date range for this period
        if period == default_period:
            main_date_range = date_range
            main_domain_name = domain_name
    
    # Generate tab navigation HTML
    tabs_html = '<div class="tabs">'
    for period in meaningful_periods:
        active_class = 'active' if period == default_period else ''
        period_name = period_display_names.get(period, period)
        tabs_html += f'<button class="tab-button {active_class}" onclick="showPeriod(\'{period}\')">{period_name}</button>'
    tabs_html += '</div>'
    
    # Generate all period content HTML
    period_content_html = ''
    for period in meaningful_periods:
        display_style = 'block' if period == default_period else 'none'
        period_content_html += f'<div id="period-{period}" class="period-content" style="display: {display_style}">'
        period_content_html += period_contents[period]
        period_content_html += '</div>'
    
    # Create a JavaScript object with date ranges for each period
    js_date_ranges = "{"
    for period in meaningful_periods:
        js_date_ranges += f"'{period}': '{date_ranges[period]}',"
    js_date_ranges = js_date_ranges.rstrip(",") + "}"
    
    # JavaScript for tab switching with date range update
    tab_javascript = f'''
    <script>
    // Store date ranges for each period
    const periodDateRanges = {js_date_ranges};
    
    function showPeriod(periodId) {{
        // Hide all period content
        var periodContents = document.getElementsByClassName("period-content");
        for (var i = 0; i < periodContents.length; i++) {{
            periodContents[i].style.display = "none";
        }}
        
        // Show the selected period content
        document.getElementById("period-" + periodId).style.display = "block";
        
        // Update active tab button
        var tabButtons = document.getElementsByClassName("tab-button");
        for (var i = 0; i < tabButtons.length; i++) {{
            tabButtons[i].classList.remove("active");
        }}
        
        // Find the clicked button and make it active
        event.currentTarget.classList.add("active");
        
        // Update the date range in the header
        if (periodDateRanges[periodId]) {{
            document.getElementById("date-range-display").innerHTML = periodDateRanges[periodId];
        }}
    }}
    </script>
    '''
    
    # Construct the HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DMARC Report for {main_domain_name}</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f9f9f9;
            }}
            
            h1, h2, h3 {{
                font-weight: 500;
            }}
            
            a {{
                color: #0366d6;
                text-decoration: none;
            }}
            
            a:hover {{
                text-decoration: underline;
            }}
            
            .header {{
                text-align: center;
                margin-bottom: 10px;
            }}
            
            .header h1 {{
                margin-bottom: 5px;
                font-size: 24px;
            }}
            
            .header p {{
                color: #666;
                margin-top: 0;
            }}
            
            /* Tab styles */
            .tabs {{
                display: flex;
                border-bottom: 1px solid #ddd;
                margin-bottom: 20px;
                overflow-x: auto;
                white-space: nowrap;
            }}
            
            .tab-button {{
                background-color: transparent;
                border: none;
                outline: none;
                cursor: pointer;
                padding: 10px 15px;
                margin-right: 5px;
                font-size: 14px;
                color: #586069;
                border-bottom: 2px solid transparent;
            }}
            
            .tab-button:hover {{
                color: #0366d6;
            }}
            
            .tab-button.active {{
                color: #0366d6;
                border-bottom-color: #0366d6;
            }}
            
            .period-content {{
                display: none;
            }}
            
            #period-{default_period} {{
                display: block;
            }}
            
            .summary-box {{
                display: flex;
                justify-content: space-between;
                border: 1px solid #e1e4e8;
                border-radius: 6px;
                margin-bottom: 30px;
                background-color: white;
                overflow: hidden;
            }}
            
            .summary-item {{
                text-align: center;
                flex: 1;
                padding: 15px 10px;
                border-right: 1px solid #e1e4e8;
            }}
            
            .summary-item:last-child {{
                border-right: none;
            }}
            
            .summary-number {{
                font-size: 32px;
                font-weight: 300;
                margin: 10px 0;
                line-height: 1;
            }}
            
            .success {{ color: #6BCB77; }}
            .failure {{ color: #FF6B6B; }}
            .neutral {{ color: #70B7FF; }}
            
            .section {{
                margin-bottom: 40px;
                border-top: 1px solid #e1e4e8;
                padding-top: 20px;
            }}
            
            .source {{
                margin-bottom: 15px;
                background-color: white;
                border: 1px solid #e1e4e8;
                border-radius: 6px;
                overflow: hidden;
            }}
            
            .source-header {{
                display: flex;
                align-items: center;
                padding: 12px 15px;
                background-color: #f6f8fa;
                border-bottom: 1px solid #e1e4e8;
            }}
            
            .icon {{
                margin-right: 8px;
                font-size: 16px;
                display: flex;
                align-items: center;
                width: 16px;
                height: 16px;
            }}
            
            .favicon {{
                width: 16px;
                height: 16px;
                object-fit: contain;
            }}
            
            .domain-favicon {{
                width: 24px;
                height: 24px;
                object-fit: contain;
                margin-right: 5px;
                vertical-align: middle;
            }}
            
            .name {{
                flex-grow: 1;
                font-weight: 600;
            }}
            
            .stats {{
                display: flex;
                align-items: center;
            }}
            
            .stat-item {{
                color: #6a737d;
                font-size: 12px;
                text-transform: uppercase;
                margin: 0 5px;
                width: 90px;
                text-align: center;
            }}
            
            .stat-value {{
                margin: 0 5px;
                width: 90px;
                text-align: center;
            }}
            
            .stat-placeholder {{
                width: 90px;
                margin: 0 5px;
                /* This class is for spacing, content is not needed */
            }}
            
            .ip-row {{
                display: flex;
                padding: 10px 15px;
                border-bottom: 1px solid #e1e4e8;
            }}
            
            .ip-row:last-child {{
                border-bottom: none;
            }}
            
            .ip {{
                flex-grow: 1;
                font-family: monospace;
            }}
            
            .warning-box {{
                background-color: #FFF9C4;
                border-left: 4px solid #FBC02D;
                padding: 15px;
                margin: 15px 0;
                border-radius: 3px;
            }}
            
            .help-links {{
                list-style-type: none;
                padding-left: 5px;
                margin: 20px 0;
            }}
            
            .help-links li {{
                margin-bottom: 8px;
            }}
            
            .more-ips {{
                padding: 8px 15px;
                font-size: 13px;
                color: #6a737d;
                text-align: center;
                background-color: #f6f8fa;
                border-top: 1px solid #e1e4e8;
            }}
            
            .recommendations {{
                background-color: #f6f8fa;
                padding: 15px;
                border-radius: 6px;
                border: 1px solid #e1e4e8;
            }}
            
            .recommendations ul {{
                margin: 0;
                padding-left: 20px;
            }}
            
            .footer {{
                text-align: center;
                margin-top: 40px;
                color: #6a737d;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1><img src="https://www.google.com/s2/favicons?domain={main_domain_name}&sz=64" class="domain-favicon" onerror="this.style.display='none';" /> {main_domain_name}</h1>
            <p id="date-range-display">{main_date_range}</p>
        </div>
        
        {tabs_html}
        
        {period_content_html}
        
        {tab_javascript}
    </body>
    </html>
    """
    
    return html_content
