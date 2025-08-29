#!/usr/bin/env python3
import click
import json
import yaml
import os
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.email_parser import EmailParser
from core.header_analyzer import HeaderAnalyzer
from core.content_analyzer import ContentAnalyzer
from core.attachment_analyzer import AttachmentAnalyzer
from core.threat_intel import ThreatIntelligence
from core.risk_scorer import RiskScorer
from core.reporter import ReportGenerator

console = Console()

@click.group()
def cli():
    """Phishing Email Analyzer (PEA) - Automated phishing investigation tool"""
    pass

@cli.command()
@click.argument('email_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output directory for reports')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'pdf', 'all']), default='json', help='Output format')
@click.option('--no-intel', is_flag=True, help='Skip threat intelligence lookups')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(email_file, output, format, no_intel, verbose):
    """Analyze a single email file"""
    if verbose:
        console.print(f"[bold green]Analyzing email file: {email_file}[/bold green]")
    
    # Create output directory if specified
    if output:
        os.makedirs(output, exist_ok=True)
    
    # Initialize components
    email_parser = EmailParser()
    header_analyzer = HeaderAnalyzer()
    content_analyzer = ContentAnalyzer()
    attachment_analyzer = AttachmentAnalyzer()
    threat_intel = ThreatIntelligence()
    risk_scorer = RiskScorer()
    reporter = ReportGenerator()
    
    # Parse email
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Parsing email...", total=None)
        email_data = email_parser.parse_email(email_file)
    
    if verbose:
        console.print(Panel.fit(f"✓ Email parsed successfully\nSubject: {email_data.get('subject', 'No subject')}"))
    
    # Analyze headers
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Analyzing headers...", total=None)
        header_analysis = header_analyzer.analyze_headers(email_data.get('headers', {}))
    
    if verbose:
        console.print(Panel.fit("✓ Header analysis completed"))
    
    # Analyze content
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Analyzing content...", total=None)
        content_analysis = content_analyzer.analyze_content(email_data)
    
    if verbose:
        console.print(Panel.fit("✓ Content analysis completed"))
    
    # Analyze attachments
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Analyzing attachments...", total=None)
        attachment_analysis = attachment_analyzer.analyze_attachments(email_data.get('attachments', []))
    
    if verbose:
        console.print(Panel.fit(f"✓ Attachment analysis completed\nFound {len(attachment_analysis.get('attachments', []))} attachments"))
    
    # Threat intelligence enrichment
    threat_intel_results = {}
    if not no_intel:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Enriching with threat intelligence...", total=None)
            threat_intel_results = _enrich_with_threat_intel(
                threat_intel, email_data, header_analysis, content_analysis, attachment_analysis
            )
    
    if verbose and not no_intel:
        console.print(Panel.fit("✓ Threat intelligence enrichment completed"))
    
    # Calculate risk score
    all_results = {
        'email_data': email_data,
        'header_analysis': header_analysis,
        'content_analysis': content_analysis,
        'attachment_analysis': attachment_analysis,
        'threat_intel': threat_intel_results
    }
    
    risk_assessment = risk_scorer.calculate_risk_score(all_results)
    all_results['risk_assessment'] = risk_assessment
    
    if verbose:
        console.print(Panel.fit(f"✓ Risk assessment completed\nScore: {risk_assessment['total_score']}/100 - {risk_assessment['risk_level']}"))
    
    # Generate report
    if output:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Generating report...", total=None)
            report_paths = reporter.generate_report(all_results, output, format)
        
        console.print(Panel.fit(f"✓ Report generated at: {report_paths}"))
    
    # Display summary
    _display_summary(all_results, verbose)
    
    return all_results

def _enrich_with_threat_intel(threat_intel, email_data, header_analysis, content_analysis, attachment_analysis):
    """Enrich analysis results with threat intelligence"""
    intel_results = {
        'ips': {},
        'urls': {},
        'domains': {},
        'hashes': {}
    }
    
    # Enrich IPs from header analysis
    for received in header_analysis.get('received_chain', []):
        ip = received.get('from_ip')
        if ip and ip not in intel_results['ips']:
            intel_results['ips'][ip] = threat_intel.enrich_ip(ip)
    
    # Enrich URLs from content analysis
    for url_info in content_analysis.get('urls', []):
        url = url_info.get('url')
        if url and url not in intel_results['urls']:
            intel_results['urls'][url] = threat_intel.enrich_url(url)
            
            # Also enrich the domain
            domain = url_info.get('registered_domain')
            if domain and domain not in intel_results['domains']:
                intel_results['domains'][domain] = threat_intel.enrich_domain(domain)
    
    # Enrich domains from header analysis
    sender_domain = header_analysis.get('sender_domain')
    if sender_domain and sender_domain not in intel_results['domains']:
        intel_results['domains'][sender_domain] = threat_intel.enrich_domain(sender_domain)
    
    reply_to_domain = header_analysis.get('reply_to_domain')
    if reply_to_domain and reply_to_domain not in intel_results['domains']:
        intel_results['domains'][reply_to_domain] = threat_intel.enrich_domain(reply_to_domain)
    
    # Enrich file hashes from attachment analysis
    for attachment in attachment_analysis.get('attachments', []):
        for hash_type in ['md5', 'sha1', 'sha256']:
            file_hash = attachment.get('hashes', {}).get(hash_type)
            if file_hash and file_hash not in intel_results['hashes']:
                intel_results['hashes'][file_hash] = threat_intel.enrich_hash(file_hash, hash_type)
    
    return intel_results

def _get_risk_factor_description(factor):
    """Get description for risk factors"""
    descriptions = {
        'authentication_failure': 'SPF/DKIM/DMARC authentication failures',
        'new_domain': 'Newly registered domains (<30 days old)',
        'known_phishing_domain': 'Domains known for phishing',
        'malicious_file': 'Malicious attachments detected',
        'malicious_url': 'Malicious URLs detected',
        'suspicious_keywords': 'Suspicious keywords in content',
        'header_inconsistencies': 'Header inconsistencies found',
        'domain_mismatch': 'Domain mismatches between sender and links',
        'hidden_content': 'Hidden content detected',
        'suspicious_formatting': 'Suspicious formatting in email',
        'grammar_errors': 'Grammar errors or poor language quality',
        'urgent_language': 'Urgent or threatening language',
        'free_email_service': 'Free email service used for official communication',
        'domain_misspelling': 'Domain misspelling or homograph attack',
        'unusual_send_time': 'Email sent at unusual hours',
        'sensitive_info_request': 'Request for sensitive information',
        'base64_content': 'Base64 encoded content found',
        'embedded_form': 'Embedded forms detected',
        'tracking_pixel': 'Tracking pixels found',
        'password_protected_attachment': 'Password protected attachments',
        'invoice_attachment': 'Suspicious invoice attachments',
        'suspicious_extension': 'Files with suspicious extensions'
    }
    return descriptions.get(factor, 'Unknown risk factor')

def _extract_red_flags(analysis_results):
    """Extract specific red flags from analysis results"""
    red_flags = []
    
    # Header analysis flags
    header_analysis = analysis_results.get('header_analysis', {})
    
    # Free email service
    if header_analysis.get('free_email_service', {}).get('is_free_email', False):
        red_flags.append({
            'type': 'Sender',
            'description': f"Free email service used: {header_analysis['free_email_service']['domain']}"
        })
    
    # Domain misspelling
    if header_analysis.get('domain_misspelling', {}).get('is_misspelled', False):
        red_flags.append({
            'type': 'Sender',
            'description': f"Domain misspelling detected: {header_analysis['domain_misspelling']['suspicious_domain']}"
        })
    
    # Authentication failures
    auth_results = header_analysis.get('authentication_results', {})
    for protocol in ['spf', 'dkim', 'dmarc']:
        if auth_results.get(protocol) == 'fail':
            red_flags.append({
                'type': 'Authentication',
                'description': f"{protocol.upper()} authentication failed"
            })
    
    # Unusual send time
    if header_analysis.get('send_time_analysis', {}).get('is_unusual_time', False):
        red_flags.append({
            'type': 'Behavioral',
            'description': header_analysis['send_time_analysis']['warning']
        })
    
    # Content analysis flags
    content_analysis = analysis_results.get('content_analysis', {})
    
    # Sensitive information requests
    if content_analysis.get('sensitive_info_requests', {}).get('sensitive_request_detected', False):
        red_flags.append({
            'type': 'Content',
            'description': 'Request for sensitive information detected'
        })
    
    # Base64 content
    if content_analysis.get('base64_content', {}).get('base64_detected', False):
        red_flags.append({
            'type': 'Content',
            'description': 'Base64 encoded content found'
        })
    
    # Embedded forms
    if content_analysis.get('embedded_forms', {}).get('embedded_forms_detected', False):
        red_flags.append({
            'type': 'Content',
            'description': 'Embedded forms detected'
        })
    
    # Tracking pixels
    if content_analysis.get('tracking_pixels', {}).get('tracking_pixels_detected', False):
        red_flags.append({
            'type': 'Content',
            'description': 'Tracking pixels detected'
        })
    
    # Subject analysis
    subject_analysis = content_analysis.get('subject_analysis', {})
    if subject_analysis.get('urgency_detected', False):
        red_flags.append({
            'type': 'Subject',
            'description': 'Urgent language in subject line'
        })
    
    if subject_analysis.get('too_good_detected', False):
        red_flags.append({
            'type': 'Subject',
            'description': 'Too-good-to-be-true offer in subject'
        })
    
    if subject_analysis.get('fake_alert_detected', False):
        red_flags.append({
            'type': 'Subject',
            'description': 'Fake alert in subject line'
        })
    
    # Generic greetings
    if content_analysis.get('greeting_analysis', {}).get('is_generic', False):
        red_flags.append({
            'type': 'Content',
            'description': 'Generic greeting instead of personalized'
        })
    
    # Attachment analysis flags
    attachment_analysis = analysis_results.get('attachment_analysis', {})
    
    # Password protected attachments
    if attachment_analysis.get('password_protected_count', 0) > 0:
        red_flags.append({
            'type': 'Attachment',
            'description': 'Password protected attachments found'
        })
    
    # Invoice-related attachments
    if attachment_analysis.get('invoice_attachment_count', 0) > 0:
        red_flags.append({
            'type': 'Attachment',
            'description': 'Suspicious invoice attachments found'
        })
    
    # Suspicious extensions
    for attachment in attachment_analysis.get('attachments', []):
        if attachment.get('suspicious_extension', False):
            red_flags.append({
                'type': 'Attachment',
                'description': f"Suspicious file extension: {attachment['filename']}"
            })
    
    # Threat intelligence flags
    threat_intel = analysis_results.get('threat_intel', {})
    
    # Malicious IPs
    for ip, intel in threat_intel.get('ips', {}).items():
        vt = intel.get('virustotal', {})
        if vt.get('malicious', 0) > 0:
            red_flags.append({
                'type': 'Threat Intel',
                'description': f"Malicious IP detected: {ip} ({vt.get('malicious', 0)} detections)"
            })
    
    # Malicious domains
    for domain, intel in threat_intel.get('domains', {}).items():
        vt = intel.get('virustotal', {})
        if vt.get('malicious', 0) > 0:
            red_flags.append({
                'type': 'Threat Intel',
                'description': f"Malicious domain detected: {domain} ({vt.get('malicious', 0)} detections)"
            })
    
    # Malicious URLs
    for url, intel in threat_intel.get('urls', {}).items():
        vt = intel.get('virustotal', {})
        if vt.get('malicious', 0) > 0:
            red_flags.append({
                'type': 'Threat Intel',
                'description': f"Malicious URL detected: {url[:50]}... ({vt.get('malicious', 0)} detections)"
            })
    
    return red_flags

def _display_detailed_findings(threat_intel):
    """Display detailed threat intelligence findings"""
    # Implementation for detailed threat intelligence display
    console.print(Panel.fit("Detailed threat intelligence findings would be displayed here"))

def _display_summary(results, verbose):
    """Display analysis summary with enhanced risk factor details"""
    risk_assessment = results.get('risk_assessment', {})
    header_analysis = results.get('header_analysis', {})
    content_analysis = results.get('content_analysis', {})
    attachment_analysis = results.get('attachment_analysis', {})
    threat_intel = results.get('threat_intel', {})
    
    # Risk summary
    risk_score = risk_assessment.get('total_score', 0)
    risk_level = risk_assessment.get('risk_level', 'Unknown')
    
    if risk_score <= 30:
        risk_color = 'green'
    elif risk_score <= 60:
        risk_color = 'orange'
    else:
        risk_color = 'red'
    
    console.print(Panel.fit(
        f"[bold]Risk Assessment[/bold]\n"
        f"Score: [bold]{risk_score}/100[/bold] - "
        f"[{risk_color}]{risk_level}[/]",
        title="Summary"
    ))
    
    # Key findings table
    table = Table(title="Key Findings")
    table.add_column("Category", style="cyan")
    table.add_column("Findings", style="white")
    
    # Authentication results
    auth_results = header_analysis.get('authentication_results', {})
    auth_status = []
    for protocol in ['spf', 'dkim', 'dmarc']:
        status = auth_results.get(protocol, 'unknown')
        color = "green" if status == "pass" else "red" if status == "fail" else "yellow"
        auth_status.append(f"[{color}]{protocol.upper()}: {status}[/]")
    
    table.add_row("Authentication", " | ".join(auth_status))
    
    # URL analysis
    suspicious_urls = 0
    for url, intel in threat_intel.get('urls', {}).items():
        vt = intel.get('virustotal', {})
        if vt.get('malicious', 0) > 0:
            suspicious_urls += 1
    
    table.add_row("URLs", f"{len(content_analysis.get('urls', []))} found, {suspicious_urls} suspicious")
    
    # Attachments
    malicious_attachments = 0
    for attachment in attachment_analysis.get('attachments', []):
        vt = attachment.get('threat_intel', {}).get('virustotal', {})
        if vt.get('malicious', 0) > 0:
            malicious_attachments += 1
    
    table.add_row("Attachments", f"{len(attachment_analysis.get('attachments', []))} found, {malicious_attachments} malicious")
    
    # Keywords
    table.add_row("Suspicious Keywords", f"{len(content_analysis.get('suspicious_keywords', []))} found")
    
    console.print(table)
    
    # Risk breakdown table
    score_breakdown = risk_assessment.get('score_breakdown', {})
    if score_breakdown:
        breakdown_table = Table(title="Risk Score Breakdown")
        breakdown_table.add_column("Risk Factor", style="cyan")
        breakdown_table.add_column("Score", style="white")
        breakdown_table.add_column("Description", style="yellow")
        
        # Add rows for each risk factor
        for factor, score in score_breakdown.items():
            if score > 0:  # Only show factors that contributed to the score
                description = _get_risk_factor_description(factor)
                breakdown_table.add_row(
                    factor.replace('_', ' ').title(),
                    str(score),
                    description
                )
        
        # Add total row
        breakdown_table.add_row(
            "Total Score",
            str(risk_score),
            f"{risk_level} risk level",
            style="bold"
        )
        
        console.print(breakdown_table)
    
    # Display red flags if any
    red_flags = _extract_red_flags(results)
    if red_flags:
        red_flag_table = Table(title="🚩 Red Flags Detected", style="red")
        red_flag_table.add_column("#", style="red")
        red_flag_table.add_column("Type", style="red")
        red_flag_table.add_column("Description", style="red")
        
        for i, flag in enumerate(red_flags, 1):
            red_flag_table.add_row(str(i), flag['type'], flag['description'])
        
        console.print(red_flag_table)
    
    if verbose:
        # Display detailed threat intelligence findings
        _display_detailed_findings(threat_intel)

if __name__ == '__main__':
    cli()