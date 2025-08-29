from typing import Dict, Any, List
from datetime import datetime

class RiskScorer:
    def __init__(self):
        self.weights = {
            'authentication_failure': 15,
            'new_domain': 20,
            'known_phishing_domain': 40,
            'malicious_file': 50,
            'malicious_url': 40,
            'suspicious_keywords': 10,
            'header_inconsistencies': 15,
            'domain_mismatch': 25,
            'hidden_content': 20,
            'suspicious_formatting': 15,
            'grammar_errors': 10,
            'urgent_language': 15,
            'free_email_service': 10,
            'domain_misspelling': 30,
            'unusual_send_time': 10,
            'sensitive_info_request': 25,
            'base64_content': 15,
            'embedded_form': 20,
            'tracking_pixel': 5,
            'password_protected_attachment': 20,
            'invoice_attachment': 15,
            'suspicious_extension': 25
        }
        # Calculate the risk score function    
    def calculate_risk_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score based on analysis results with enhanced criteria"""
        score_breakdown = {}
        total_score = 0
        
        # Extract components
        header_analysis = analysis_results.get('header_analysis', {})
        content_analysis = analysis_results.get('content_analysis', {})
        attachment_analysis = analysis_results.get('attachment_analysis', {})
        threat_intel = analysis_results.get('threat_intel', {})
        
        # Authentication failures
        auth_failures = self._check_auth_failures(header_analysis)
        score_breakdown['authentication_failure'] = auth_failures * self.weights['authentication_failure']
        total_score += score_breakdown['authentication_failure']
        
        # Domain age analysis
        new_domains = self._check_new_domains(content_analysis, threat_intel)
        score_breakdown['new_domain'] = new_domains * self.weights['new_domain']
        total_score += score_breakdown['new_domain']
        
        # Known phishing domains
        phishing_domains = self._check_phishing_domains(threat_intel)
        score_breakdown['known_phishing_domain'] = phishing_domains * self.weights['known_phishing_domain']
        total_score += score_breakdown['known_phishing_domain']
        
        # Malicious files
        malicious_files = self._check_malicious_files(attachment_analysis)
        score_breakdown['malicious_file'] = malicious_files * self.weights['malicious_file']
        total_score += score_breakdown['malicious_file']
        
        # Malicious URLs
        malicious_urls = self._check_malicious_urls(threat_intel)
        score_breakdown['malicious_url'] = malicious_urls * self.weights['malicious_url']
        total_score += score_breakdown['malicious_url']
        
        # Suspicious keywords
        suspicious_keywords = len(content_analysis.get('suspicious_keywords', []))
        score_breakdown['suspicious_keywords'] = min(suspicious_keywords, 5) * self.weights['suspicious_keywords']
        total_score += score_breakdown['suspicious_keywords']
        
        # Header inconsistencies
        inconsistencies = len(header_analysis.get('header_inconsistencies', []))
        score_breakdown['header_inconsistencies'] = min(inconsistencies, 3) * self.weights['header_inconsistencies']
        total_score += score_breakdown['header_inconsistencies']
        
        # Domain mismatches
        domain_mismatches = len(content_analysis.get('domain_mismatch', []))
        score_breakdown['domain_mismatch'] = min(domain_mismatches, 3) * self.weights['domain_mismatch']
        total_score += score_breakdown['domain_mismatch']
        
        # Hidden content
        hidden_content = len(content_analysis.get('hidden_text', []))
        score_breakdown['hidden_content'] = min(hidden_content, 3) * self.weights['hidden_content']
        total_score += score_breakdown['hidden_content']
        
        # Suspicious formatting
        formatting_issues = len(content_analysis.get('formatting_analysis', {}).get('link_text_mismatch', []))
        score_breakdown['suspicious_formatting'] = min(formatting_issues, 3) * self.weights['suspicious_formatting']
        total_score += score_breakdown['suspicious_formatting']
        
        # Grammar errors
        grammar_errors = 1 if content_analysis.get('language_analysis', {}).get('has_grammar_errors', False) else 0
        score_breakdown['grammar_errors'] = grammar_errors * self.weights['grammar_errors']
        total_score += score_breakdown['grammar_errors']
        
        # Urgent language
        urgent_language = 1 if content_analysis.get('language_analysis', {}).get('has_urgent_language', False) else 0
        score_breakdown['urgent_language'] = urgent_language * self.weights['urgent_language']
        total_score += score_breakdown['urgent_language']
        
        # NEW: Free email service
        free_email = 1 if header_analysis.get('free_email_service', {}).get('is_free_email', False) else 0
        score_breakdown['free_email_service'] = free_email * self.weights['free_email_service']
        total_score += score_breakdown['free_email_service']
        
        # NEW: Domain misspelling
        domain_misspelling = 1 if header_analysis.get('domain_misspelling', {}).get('is_misspelled', False) else 0
        score_breakdown['domain_misspelling'] = domain_misspelling * self.weights['domain_misspelling']
        total_score += score_breakdown['domain_misspelling']
        
        # NEW: Unusual send time
        unusual_time = 1 if header_analysis.get('send_time_analysis', {}).get('is_unusual_time', False) else 0
        score_breakdown['unusual_send_time'] = unusual_time * self.weights['unusual_send_time']
        total_score += score_breakdown['unusual_send_time']
        
        # NEW: Sensitive info requests
        sensitive_info = 1 if content_analysis.get('sensitive_info_requests', {}).get('sensitive_request_detected', False) else 0
        score_breakdown['sensitive_info_request'] = sensitive_info * self.weights['sensitive_info_request']
        total_score += score_breakdown['sensitive_info_request']
        
        # NEW: Base64 content
        base64_content = 1 if content_analysis.get('base64_content', {}).get('base64_detected', False) else 0
        score_breakdown['base64_content'] = base64_content * self.weights['base64_content']
        total_score += score_breakdown['base64_content']
        
        # NEW: Embedded forms
        embedded_form = 1 if content_analysis.get('embedded_forms', {}).get('embedded_forms_detected', False) else 0
        score_breakdown['embedded_form'] = embedded_form * self.weights['embedded_form']
        total_score += score_breakdown['embedded_form']
        
        # NEW: Tracking pixels
        tracking_pixel = 1 if content_analysis.get('tracking_pixels', {}).get('tracking_pixels_detected', False) else 0
        score_breakdown['tracking_pixel'] = tracking_pixel * self.weights['tracking_pixel']
        total_score += score_breakdown['tracking_pixel']
        
        # NEW: Password protected attachments
        password_attachments = attachment_analysis.get('password_protected_count', 0)
        score_breakdown['password_protected_attachment'] = min(password_attachments, 3) * self.weights['password_protected_attachment']
        total_score += score_breakdown['password_protected_attachment']
        
        # NEW: Invoice attachments
        invoice_attachments = attachment_analysis.get('invoice_attachment_count', 0)
        score_breakdown['invoice_attachment'] = min(invoice_attachments, 3) * self.weights['invoice_attachment']
        total_score += score_breakdown['invoice_attachment']
        
        # NEW: Suspicious extensions
        suspicious_extensions = sum(1 for att in attachment_analysis.get('attachments', []) 
                                  if att.get('suspicious_extension', False))
        score_breakdown['suspicious_extension'] = min(suspicious_extensions, 3) * self.weights['suspicious_extension']
        total_score += score_breakdown['suspicious_extension']
        
        # Cap the score at 100
        total_score = min(total_score, 100)
        
        # Determine risk level
        risk_level = self._determine_risk_level(total_score)
        
        return {
            'total_score': total_score,
            'risk_level': risk_level,
            'score_breakdown': score_breakdown
        }
    
    def _check_auth_failures(self, header_analysis: Dict[str, Any]) -> int:
        """Check for authentication failures"""
        failures = 0
        if header_analysis.get('spf_result') == 'fail':
            failures += 1
        if header_analysis.get('dkim_result') == 'fail':
            failures += 1
        if header_analysis.get('dmarc_result') == 'fail':
            failures += 1
        return min(failures, 2)  # Cap at 2 to avoid excessive scoring
    
    def _check_new_domains(self, content_analysis: Dict[str, Any], threat_intel: Dict[str, Any]) -> int:
        """Check for newly registered domains"""
        new_domains = 0
        urls = content_analysis.get('urls', [])
        
        for url in urls:
            domain = url.get('registered_domain', '')
            if domain:
                domain_info = threat_intel.get('domains', {}).get(domain, {})
                domain_age = domain_info.get('domain_age')
                if domain_age is not None and domain_age < 30:  # Less than 30 days old
                    new_domains += 1
        
        return min(new_domains, 3)  # Cap at 3
    
    def _check_phishing_domains(self, threat_intel: Dict[str, Any]) -> int:
        """Check for known phishing domains"""
        phishing_domains = 0
        domains = threat_intel.get('domains', {})
        
        for domain, info in domains.items():
            # Check VirusTotal
            vt_info = info.get('virustotal', {})
            if vt_info.get('malicious', 0) > 0 or vt_info.get('suspicious', 0) > 0:
                phishing_domains += 1
            
            # Check PhishTank
            pt_info = info.get('phishtank', {})
            if pt_info.get('in_database', False) and pt_info.get('verified', False):
                phishing_domains += 1
        
        return min(phishing_domains, 3)  # Cap at 3
    
    def _check_malicious_files(self, attachment_analysis: Dict[str, Any]) -> int:
        """Check for malicious files"""
        malicious_files = 0
        attachments = attachment_analysis.get('attachments', [])
        
        for attachment in attachments:
            threat_info = attachment.get('threat_intel', {})
            vt_info = threat_info.get('virustotal', {})
            if vt_info.get('malicious', 0) > 0:
                malicious_files += 1
        
        return min(malicious_files, 3)  # Cap at 3
    
    def _check_malicious_urls(self, threat_intel: Dict[str, Any]) -> int:
        """Check for malicious URLs"""
        malicious_urls = 0
        urls = threat_intel.get('urls', {})
        
        for url, info in urls.items():
            # Check VirusTotal
            vt_info = info.get('virustotal', {})
            if vt_info.get('malicious', 0) > 0:
                malicious_urls += 1
            
            # Check URLhaus
            uh_info = info.get('urlhaus', {})
            if uh_info.get('threat') and uh_info.get('threat') != 'not_found':
                malicious_urls += 1
            
            # Check PhishTank
            pt_info = info.get('phishtank', {})
            if pt_info.get('in_database', False) and pt_info.get('verified', False):
                malicious_urls += 1
        
        return min(malicious_urls, 3)  # Cap at 3
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level based on score"""
        if score <= 30:
            return "Low Risk"
        elif score <= 60:
            return "Medium Risk"
        else:
            return "High Risk"