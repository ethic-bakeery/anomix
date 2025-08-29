import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import jinja2
import pdfkit

class ReportGenerator:
    def __init__(self):
        self.template_loader = jinja2.FileSystemLoader(searchpath="./templates")
        self.template_env = jinja2.Environment(loader=self.template_loader)
    
    def generate_report(self, analysis_results: Dict[str, Any], output_dir: str, format: str = 'json') -> List[str]:
        """Generate reports in specified formats"""
        output_paths = []
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate base filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        subject = analysis_results.get('email_data', {}).get('subject', 'unknown')
        safe_subject = "".join(c for c in subject if c.isalnum() or c in (' ', '-', '_')).rstrip()
        safe_subject = safe_subject[:50]  # Limit length
        base_filename = f"phishing_report_{safe_subject}_{timestamp}"
        
        # Generate reports in requested formats
        if format in ['json', 'all']:
            json_path = self._generate_json_report(analysis_results, output_dir, base_filename)
            output_paths.append(json_path)
        
        if format in ['html', 'all']:
            html_path = self._generate_html_report(analysis_results, output_dir, base_filename)
            output_paths.append(html_path)
        
        if format in ['pdf', 'all']:
            pdf_path = self._generate_pdf_report(analysis_results, output_dir, base_filename)
            output_paths.append(pdf_path)
        
        return output_paths
    
    def _generate_json_report(self, analysis_results: Dict[str, Any], output_dir: str, base_filename: str) -> str:
        """Generate JSON report"""
        filename = f"{base_filename}.json"
        filepath = os.path.join(output_dir, filename)
        
        # Create a simplified version for JSON output
        simplified_results = self._simplify_for_json(analysis_results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(simplified_results, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def _simplify_for_json(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Simplify analysis results for JSON output"""
        # Remove large binary data and other non-serializable content
        simplified = analysis_results.copy()
        
        # Clean email data
        email_data = simplified.get('email_data', {})
        if 'attachments' in email_data:
            for attachment in email_data['attachments']:
                if 'payload' in attachment:
                    attachment['payload'] = f"<binary data: {len(attachment['payload'])} bytes>"
        
        # Clean attachment analysis
        attachment_analysis = simplified.get('attachment_analysis', {})
        for attachment in attachment_analysis.get('attachments', []):
            if 'macro_analysis' in attachment and 'extracted_code' in attachment['macro_analysis']:
                attachment['macro_analysis']['extracted_code'] = attachment['macro_analysis']['extracted_code'][:500] + "..." if len(attachment['macro_analysis']['extracted_code']) > 500 else attachment['macro_analysis']['extracted_code']
        
        return simplified
    
    def _generate_html_report(self, analysis_results: Dict[str, Any], output_dir: str, base_filename: str) -> str:
        """Generate HTML report using Jinja2 template"""
        filename = f"{base_filename}.html"
        filepath = os.path.join(output_dir, filename)
        
        try:
            template = self.template_env.get_template('report_template.html')
        except jinja2.TemplateNotFound:
            # Fallback to basic HTML if template not found
            html_content = self._generate_basic_html(analysis_results)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return filepath
        
        # Prepare data for template
        template_data = self._prepare_template_data(analysis_results)
        
        # Render template
        html_content = template.render(**template_data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_pdf_report(self, analysis_results: Dict[str, Any], output_dir: str, base_filename: str) -> str:
        """Generate PDF report"""
        filename = f"{base_filename}.pdf"
        filepath = os.path.join(output_dir, filename)
        
        # First generate HTML
        html_content = self._generate_basic_html(analysis_results)
        
        # Convert to PDF
        try:
            pdfkit.from_string(html_content, filepath, options={
                'page-size': 'A4',
                'margin-top': '0.5in',
                'margin-right': '0.5in',
                'margin-bottom': '0.5in',
                'margin-left': '0.5in',
                'encoding': "UTF-8",
                'no-outline': None
            })
        except Exception as e:
            # Fallback: save as HTML if PDF generation fails
            fallback_filename = f"{base_filename}_PDF_FAILED.html"
            fallback_path = os.path.join(output_dir, fallback_filename)
            with open(fallback_path, 'w', encoding='utf-8') as f:
                f.write(f"<!-- PDF generation failed: {str(e)} -->\n")
                f.write(html_content)
            return fallback_path
        
        return filepath
    
    def _prepare_template_data(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for HTML template"""
        email_data = analysis_results.get('email_data', {})
        header_analysis = analysis_results.get('header_analysis', {})
        content_analysis = analysis_results.get('content_analysis', {})
        attachment_analysis = analysis_results.get('attachment_analysis', {})
        threat_intel = analysis_results.get('threat_intel', {})
        risk_assessment = analysis_results.get('risk_assessment', {})
        
        # Format dates
        email_date = email_data.get('date', '')
        if email_date:
            try:
                from email.utils import parsedate_to_datetime
                email_date = parsedate_to_datetime(email_date).strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        
        # Prepare URL analysis
        url_analysis = []
        for url_info in content_analysis.get('urls', []):
            url = url_info.get('url', '')
            intel = threat_intel.get('urls', {}).get(url, {})
            url_analysis.append({
                'url': url,
                'domain': url_info.get('registered_domain', ''),
                'suspicious_tld': url_info.get('suspicious_tld', False),
                'is_shortened': url_info.get('is_shortened', False),
                'virustotal': intel.get('virustotal', {}),
                'urlhaus': intel.get('urlhaus', {}),
                'phishtank': intel.get('phishtank', {})
            })
        
        # Prepare attachment analysis
        attachments_formatted = []
        for attachment in attachment_analysis.get('attachments', []):
            hashes = attachment.get('hashes', {})
            intel = threat_intel.get('hashes', {}).get(hashes.get('sha256', ''), {})
            attachments_formatted.append({
                'filename': attachment.get('filename', ''),
                'size': attachment.get('size', 0),
                'file_type': attachment.get('file_type', ''),
                'threat_level': attachment.get('threat_level', 'clean'),
                'hashes': hashes,
                'virustotal': intel.get('virustotal', {}),
                'indicators': attachment.get('indicators', [])
            })
        
        # Prepare IP analysis
        ip_analysis = []
        for received in header_analysis.get('received_chain', []):
            ip = received.get('from_ip', '')
            if ip:
                intel = threat_intel.get('ips', {}).get(ip, {})
                ip_analysis.append({
                    'ip': ip,
                    'timestamp': received.get('timestamp', ''),
                    'virustotal': intel.get('virustotal', {}),
                    'abuseipdb': intel.get('abuseipdb', {}),
                    'greynoise': intel.get('greynoise', {}),
                    'geoip': intel.get('geoip', {})
                })
        
        return {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'email_data': email_data,
            'email_date': email_date,
            'header_analysis': header_analysis,
            'content_analysis': content_analysis,
            'attachment_analysis': attachment_analysis,
            'threat_intel': threat_intel,
            'risk_assessment': risk_assessment,
            'url_analysis': url_analysis,
            'attachments_formatted': attachments_formatted,
            'ip_analysis': ip_analysis
        }
    
    def _generate_basic_html(self, analysis_results: Dict[str, Any]) -> str:
        """Generate basic HTML report without template"""
        template_data = self._prepare_template_data(analysis_results)
        
        risk_score = template_data['risk_assessment'].get('total_score', 0)
        risk_level = template_data['risk_assessment'].get('risk_level', 'Unknown')
        
        if risk_score <= 30:
            risk_color = 'green'
        elif risk_score <= 60:
            risk_color = 'orange'
        else:
            risk_color = 'red'
        
        # Generate IP rows
        ip_rows = ""
        for ip_info in template_data['ip_analysis']:
            ip_rows += f"""
                <tr>
                    <td>{ip_info['ip']}</td>
                    <td>{ip_info['timestamp']}</td>
                    <td>{ip_info['virustotal'].get('malicious', 0)} malicious detections</td>
                </tr>
            """
        
        # Generate URL rows
        url_rows = ""
        for url_info in template_data['url_analysis']:
            urlhaus_status = 'Threat detected' if url_info['urlhaus'].get('threat') and url_info['urlhaus']['threat'] != 'not_found' else 'Clean'
            url_rows += f"""
                <tr>
                    <td>{url_info['url'][:50]}...</td>
                    <td>{url_info['domain']}</td>
                    <td>{url_info['virustotal'].get('malicious', 0)} malicious</td>
                    <td>{urlhaus_status}</td>
                </tr>
            """
        
        # Generate attachment rows
        attachment_rows = ""
        for att in template_data['attachments_formatted']:
            attachment_rows += f"""
                <tr>
                    <td>{att['filename']}</td>
                    <td>{att['file_type']}</td>
                    <td>{att['size']} bytes</td>
                    <td class="risk-{att['threat_level']}">{att['threat_level']}</td>
                    <td>{att['virustotal'].get('malicious', 0)} malicious</td>
                </tr>
            """
        
        # Generate risk breakdown rows
        risk_rows = ""
        for category, score in template_data['risk_assessment'].get('score_breakdown', {}).items():
            risk_rows += f"""
                <tr>
                    <td>{category}</td>
                    <td>{score}</td>
                </tr>
            """
        
        # Determine recommended action
        if risk_level == "Low Risk":
            recommended_action = "Likely safe, no action needed"
        elif risk_level == "Medium Risk":
            recommended_action = "Suspicious, review carefully"
        else:
            recommended_action = "Highly likely phishing, quarantine and investigate"
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Phishing Email Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                h1 {{ color: #333; border-bottom: 2px solid #333; }}
                h2 {{ color: #555; margin-top: 30px; }}
                h3 {{ color: #777; }}
                .risk-high {{ color: red; font-weight: bold; }}
                .risk-medium {{ color: orange; font-weight: bold; }}
                .risk-low {{ color: green; font-weight: bold; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .indicator {{ background-color: #ffe6e6; padding: 5px; margin: 2px; border-radius: 3px; }}
                .summary {{ background-color: #f0f8ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1>Phishing Email Analysis Report</h1>
            <p>Generated on: {template_data['timestamp']}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Subject:</strong> {template_data['email_data'].get('subject', 'No subject')}</p>
                <p><strong>From:</strong> {template_data['email_data'].get('from', 'Unknown')}</p>
                <p><strong>To:</strong> {template_data['email_data'].get('to', 'Unknown')}</p>
                <p><strong>Date:</strong> {template_data['email_date']}</p>
                <p><strong>Risk Score:</strong> <span class="risk-{risk_color}">{risk_score}/100 - {risk_level}</span></p>
            </div>
            
            <h2>Header Analysis</h2>
            <p><strong>SPF:</strong> {template_data['header_analysis'].get('spf_result', 'Unknown')}</p>
            <p><strong>DKIM:</strong> {template_data['header_analysis'].get('dkim_result', 'Unknown')}</p>
            <p><strong>DMARC:</strong> {template_data['header_analysis'].get('dmarc_result', 'Unknown')}</p>
            
            <h3>Received Headers</h3>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Timestamp</th>
                    <th>Reputation</th>
                </tr>
                {ip_rows}
            </table>
            
            <h2>Content Analysis</h2>
            <p><strong>Suspicious Keywords Found:</strong> {len(template_data['content_analysis'].get('suspicious_keywords', []))}</p>
            
            <h3>URLs Found</h3>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Domain</th>
                    <th>VirusTotal</th>
                    <th>URLHaus</th>
                </tr>
                {url_rows}
            </table>
            
            <h2>Attachment Analysis</h2>
            <p><strong>Total Attachments:</strong> {template_data['attachment_analysis'].get('total_count', 0)}</p>
            <p><strong>Malicious Attachments:</strong> {template_data['attachment_analysis'].get('malicious_count', 0)}</p>
            
            <h3>Attachment Details</h3>
            <table>
                <tr>
                    <th>Filename</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Threat Level</th>
                    <th>VirusTotal</th>
                </tr>
                {attachment_rows}
            </table>
            
            <h2>Risk Assessment Breakdown</h2>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Score</th>
                </tr>
                {risk_rows}
                <tr>
                    <td><strong>Total Score</strong></td>
                    <td><strong>{risk_score}</strong></td>
                </tr>
            </table>
            
            <h2>Conclusion</h2>
            <p>This email has been classified as <strong class="risk-{risk_color}">{risk_level}</strong>.</p>
            <p>Recommended action: {recommended_action}</p>
        </body>
        </html>
        """
        
        return html