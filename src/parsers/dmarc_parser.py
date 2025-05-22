"""
DMARC Report Parser

This module handles the parsing of DMARC XML reports,
including extraction from various file formats (XML, gzip, zip).
"""

import os
import sys
import gzip
import zipfile
from datetime import datetime

try:
    import xml.etree.ElementTree as ET_stdlib  # Keep for ParseError if needed
    from defusedxml import ElementTree as ET
    from defusedxml.common import DefusedXmlException, EntitiesForbidden, ExternalReferenceForbidden
except ImportError:
    print("Error: 'defusedxml' library is required. Please install it via pip: pip install defusedxml", file=sys.stderr)
    sys.exit(1)


def extract_xml_from_file(filepath):
    """
    Extract XML content from a file, handling different compression formats.
    
    Args:
        filepath: Path to the DMARC report file (can be .xml, .gz, or .zip)
        
    Returns:
        str: The XML content as string, or None if extraction failed
    """
    if filepath.endswith('.xml'):
        with open(filepath, 'r') as f:
            return f.read()
    elif filepath.endswith('.gz'):
        with gzip.open(filepath, 'rt') as f:
            return f.read()
    elif filepath.endswith('.zip'):
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            # Assume there's only one XML file in the ZIP
            xml_files = [f for f in zip_ref.namelist() if f.endswith('.xml')]
            if xml_files:
                with zip_ref.open(xml_files[0]) as f:
                    return f.read().decode('utf-8')
    return None


def parse_dmarc_report(xml_content):
    """
    Parse DMARC report XML content and extract relevant information.
    
    Args:
        xml_content: XML content as string
        
    Returns:
        dict: Structured data extracted from the DMARC report, or None if parsing failed
    """
    if not xml_content:
        return None
    
    try:
        root = ET.fromstring(xml_content)
        
        # Extract report metadata
        report_metadata = {}
        metadata_elem = root.find('.//report_metadata')
        if metadata_elem is not None:
            org_name_elem = metadata_elem.find('org_name')
            report_metadata['org_name'] = org_name_elem.text if org_name_elem is not None else 'Unknown'
            
            email_elem = metadata_elem.find('email')
            report_metadata['email'] = email_elem.text if email_elem is not None else 'Unknown'
            
            date_range_elem = metadata_elem.find('date_range')
            if date_range_elem is not None:
                begin_elem = date_range_elem.find('begin')
                end_elem = date_range_elem.find('end')
                if begin_elem is not None and end_elem is not None:
                    begin_timestamp = int(begin_elem.text)
                    end_timestamp = int(end_elem.text)
                    report_metadata['begin_date_dt'] = datetime.fromtimestamp(begin_timestamp)
                    report_metadata['end_date_dt'] = datetime.fromtimestamp(end_timestamp)
                    report_metadata['begin_date'] = report_metadata['begin_date_dt'].strftime('%Y-%m-%d %H:%M:%S')
                    report_metadata['end_date'] = report_metadata['end_date_dt'].strftime('%Y-%m-%d %H:%M:%S')
        
        # Extract policy published
        policy_published = {}
        policy_elem = root.find('.//policy_published')
        if policy_elem is not None:
            domain_elem = policy_elem.find('domain')
            policy_published['domain'] = domain_elem.text if domain_elem is not None else 'Unknown'
            
            p_elem = policy_elem.find('p')
            policy_published['policy'] = p_elem.text if p_elem is not None else 'none'
            
            sp_elem = policy_elem.find('sp')
            policy_published['subpolicy'] = sp_elem.text if sp_elem is not None else policy_published.get('policy', 'none')
            
            pct_elem = policy_elem.find('pct')
            policy_published['pct'] = pct_elem.text if pct_elem is not None else '100'
        
        # Extract records
        records = []
        for record_elem in root.findall('.//record'):
            record = {}
            
            # Source IP
            source_ip_elem = record_elem.find('.//source_ip')
            record['source_ip'] = source_ip_elem.text if source_ip_elem is not None else 'Unknown'
            
            # Count
            count_elem = record_elem.find('.//count')
            record['count'] = int(count_elem.text) if count_elem is not None else 0
            
            # Policy evaluated
            policy_evaluated_elem = record_elem.find('.//policy_evaluated')
            if policy_evaluated_elem is not None:
                disposition_elem = policy_evaluated_elem.find('disposition')
                record['disposition'] = disposition_elem.text if disposition_elem is not None else 'Unknown'
                
                dkim_elem = policy_evaluated_elem.find('dkim')
                record['dkim_result'] = dkim_elem.text if dkim_elem is not None else 'Unknown'
                
                spf_elem = policy_evaluated_elem.find('spf')
                record['spf_result'] = spf_elem.text if spf_elem is not None else 'Unknown'
            
            # Identifiers
            identifiers_elem = record_elem.find('.//identifiers')
            if identifiers_elem is not None:
                header_from_elem = identifiers_elem.find('header_from')
                record['header_from'] = header_from_elem.text if header_from_elem is not None else 'Unknown'
            
            # Auth results
            auth_results_elem = record_elem.find('.//auth_results')
            if auth_results_elem is not None:
                # DKIM
                dkim_elems = auth_results_elem.findall('.//dkim')
                record['dkim_auth'] = []
                for dkim_elem in dkim_elems:
                    dkim_domain_elem = dkim_elem.find('domain')
                    dkim_result_elem = dkim_elem.find('result')
                    if dkim_domain_elem is not None and dkim_result_elem is not None:
                        record['dkim_auth'].append({
                            'domain': dkim_domain_elem.text,
                            'result': dkim_result_elem.text
                        })
                
                # SPF
                spf_elems = auth_results_elem.findall('.//spf')
                record['spf_auth'] = []
                for spf_elem in spf_elems:
                    spf_domain_elem = spf_elem.find('domain')
                    spf_result_elem = spf_elem.find('result')
                    if spf_domain_elem is not None and spf_result_elem is not None:
                        record['spf_auth'].append({
                            'domain': spf_domain_elem.text,
                            'result': spf_result_elem.text
                        })
            
            records.append(record)
        
        return {
            'metadata': report_metadata,
            'policy_published': policy_published,
            'records': records
        }
    
    except (ET_stdlib.ParseError, DefusedXmlException, EntitiesForbidden, ExternalReferenceForbidden) as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return None
