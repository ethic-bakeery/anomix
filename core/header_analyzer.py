import re
import ipaddress
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
import tldextract
from datetime import datetime
import idna

class HeaderAnalyzer:
    def __init__(self):
        self.tld_extract = tldextract.TLDExtract(cache_dir=False)
        self.free_email_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'protonmail.com', 'icloud.com', 'mail.com', 'zoho.com', 'yandex.com'
        }
        self.common_brands = {
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix',
            'bankofamerica', 'wellsfargo', 'chase', 'facebook', 'twitter'
        }
    
    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze email headers for suspicious patterns"""
        analysis = {
            'spf_result': self._check_spf(headers),
            'dkim_result': self._check_dkim(headers),
            'dmarc_result': self._check_dmarc(headers),
            'sender_domain': self._extract_sender_domain(headers),
            'reply_to_domain': self._extract_reply_to_domain(headers),
            'received_chain': self._analyze_received_chain(headers),
            'x_headers': self._analyze_x_headers(headers),
            'authentication_results': self._parse_auth_results(headers),
            'message_id_analysis': self._analyze_message_id(headers),
            'header_inconsistencies': self._find_inconsistencies(headers),
            'free_email_service': self._check_free_email_service(headers),
            'domain_misspelling': self._check_domain_misspelling(headers),
            'domain_age_info': self._get_domain_age_info(headers),
            'send_time_analysis': self._analyze_send_time(headers)
            # I will add more features in the future implementation
        }
        
        return analysis
    
    def _check_spf(self, headers: Dict[str, str]) -> str:
        """Check SPF authentication results"""
        for key in ['Authentication-Results', 'Received-SPF']:
            if key in headers:
                if 'spf=pass' in headers[key].lower():
                    return 'pass'
                elif 'spf=fail' in headers[key].lower():
                    return 'fail'
                elif 'spf=softfail' in headers[key].lower():
                    return 'softfail'
        return 'unknown'
    
    def _check_dkim(self, headers: Dict[str, str]) -> str:
        """Check DKIM authentication results"""
        for key in ['Authentication-Results', 'DKIM-Signature']:
            if key in headers:
                if 'dkim=pass' in headers[key].lower() or 'dkim-signature' in headers[key].lower():
                    return 'pass'
                elif 'dkim=fail' in headers[key].lower():
                    return 'fail'
        return 'unknown'
    
    def _check_dmarc(self, headers: Dict[str, str]) -> str:
        """Check DMARC authentication results"""
        for key in ['Authentication-Results', 'DMARC']:
            if key in headers:
                if 'dmarc=pass' in headers[key].lower():
                    return 'pass'
                elif 'dmarc=fail' in headers[key].lower():
                    return 'fail'
        return 'unknown'
    
    def _extract_sender_domain(self, headers: Dict[str, str]) -> str:
        """Extract domain from sender address"""
        from_header = headers.get('From', '')
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_header)
        if email_match:
            return email_match.group(1)
        return ''
    
    def _extract_reply_to_domain(self, headers: Dict[str, str]) -> str:
        """Extract domain from reply-to address"""
        reply_to = headers.get('Reply-To', '')
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', reply_to)
        if email_match:
            return email_match.group(1)
        return ''
    
    def _analyze_received_chain(self, headers: Dict[str, str]) -> List[Dict]:
        """Analyze the received header chain"""
        received_headers = [v for k, v in headers.items() if k.lower() == 'received']
        chain = []
        
        for header in received_headers:
            analysis = {
                'from_ip': self._extract_ip_from_received(header),
                'by_domain': self._extract_by_domain(header),
                'with_protocol': self._extract_protocol(header),
                'timestamp': self._extract_timestamp(header)
            }
            chain.append(analysis)
        
        return chain
    
    def _extract_ip_from_received(self, header: str) -> str:
        """Extract IP address from received header"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, header)
        return match.group(0) if match else ''
    
    def _extract_by_domain(self, header: str) -> str:
        """Extract by domain from received header"""
        pattern = r'by\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        match = re.search(pattern, header, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def _extract_protocol(self, header: str) -> str:
        """Extract protocol from received header"""
        protocols = ['smtp', 'esmtp', 'http', 'https']
        for protocol in protocols:
            if protocol in header.lower():
                return protocol
        return 'unknown'
    
    def _extract_timestamp(self, header: str) -> str:
        """Extract timestamp from received header"""
        # This is a simplified version - would need more robust parsing
        date_pattern = r';\s*([A-Za-z]{3},\s*\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})'
        match = re.search(date_pattern, header)
        return match.group(1) if match else ''
    
    def _analyze_x_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Analyze X- headers for suspicious values"""
        x_headers = {}
        suspicious_patterns = ['x-mailer', 'x-originating-ip', 'x-priority', 'x-msmail-priority']
        
        for key, value in headers.items():
            if key.lower().startswith('x-') and any(pattern in key.lower() for pattern in suspicious_patterns):
                x_headers[key] = value
        
        return x_headers
    
    def _parse_auth_results(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Parse authentication results header"""
        auth_results = {}
        if 'Authentication-Results' in headers:
            # Simple parsing - could be enhanced
            results = headers['Authentication-Results']
            if 'spf=' in results:
                spf_match = re.search(r'spf=(\w+)', results)
                if spf_match:
                    auth_results['spf'] = spf_match.group(1)
            if 'dkim=' in results:
                dkim_match = re.search(r'dkim=(\w+)', results)
                if dkim_match:
                    auth_results['dkim'] = dkim_match.group(1)
            if 'dmarc=' in results:
                dmarc_match = re.search(r'dmarc=(\w+)', results)
                if dmarc_match:
                    auth_results['dmarc'] = dmarc_match.group(1)
        
        return auth_results
    
    def _analyze_message_id(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze Message-ID header for inconsistencies"""
        message_id = headers.get('Message-ID', '')
        analysis = {
            'message_id': message_id,
            'domain_match': True  # Default to True, will check below
        }
        
        if message_id and '@' in message_id:
            # Extract domain from Message-ID
            msg_id_domain = message_id.split('@')[1].strip('>')
            
            # Compare with sender domain
            sender_domain = self._extract_sender_domain(headers)
            if sender_domain and msg_id_domain != sender_domain:
                analysis['domain_match'] = False
                analysis['message_id_domain'] = msg_id_domain
                analysis['sender_domain'] = sender_domain
        
        return analysis
    
    def _find_inconsistencies(self, headers: Dict[str, str]) -> List[str]:
        """Find inconsistencies in headers"""
        inconsistencies = []
        
        # Check if From and Reply-To domains match
        from_domain = self._extract_sender_domain(headers)
        reply_to_domain = self._extract_reply_to_domain(headers)
        
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            inconsistencies.append(f"From domain ({from_domain}) doesn't match Reply-To domain ({reply_to_domain})")
        
        # Check for missing important headers
        important_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID']
        for header in important_headers:
            if header not in headers:
                inconsistencies.append(f"Missing important header: {header}")
        
        # Check for suspicious X-Headers
        x_headers = self._analyze_x_headers(headers)
        suspicious_x_headers = [
            'X-Priority', 'X-MSMail-Priority', 'X-Mailer', 
            'X-MimeOLE', 'X-Originating-IP'
        ]
        
        for x_header in suspicious_x_headers:
            if x_header in x_headers:
                inconsistencies.append(f"Suspicious X-Header found: {x_header} = {x_headers[x_header]}")
        
        return inconsistencies
    
    # NEW METHODS FOR ENHANCED DETECTION
    def _check_free_email_service(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check if sender uses free email service for official communication"""
        from_domain = self._extract_sender_domain(headers)
        result = {
            'is_free_email': False,
            'domain': from_domain,
            'warning': None
        }
        
        if from_domain and any(free_domain in from_domain for free_domain in self.free_email_domains):
            result['is_free_email'] = True
            result['warning'] = f"Free email service used: {from_domain}"
        
        return result
    
    def _check_domain_misspelling(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check for domain misspellings or lookalike domains"""
        from_domain = self._extract_sender_domain(headers)
        result = {
            'is_misspelled': False,
            'original_domain': from_domain,
            'suspicious_domain': None,
            'potential_targets': []
        }
        
        if from_domain:
            # Check for common misspellings
            for brand in self.common_brands:
                if brand in from_domain:
                    # Check for common misspellings
                    common_misspellings = {
                        'paypal': ['paypa1', 'paypai', 'paypaI', 'paypa|'],
                        'amazon': ['amaz0n', 'amaz0n', 'amazonn', 'amazom'],
                        'microsoft': ['micros0ft', 'microsoftt', 'mircosoft', 'microssoft'],
                        'apple': ['app1e', 'appie', 'aple'],
                        'google': ['g00gle', 'go0gle', 'goggle', 'googIe']
                    }
                    
                    if brand in common_misspellings:
                        for misspelling in common_misspellings[brand]:
                            if misspelling in from_domain:
                                result['is_misspelled'] = True
                                result['suspicious_domain'] = from_domain
                                result['potential_targets'].append(brand)
                                break
            
            # Check for homograph attacks using IDNA
            try:
                idna_encoded = idna.encode(from_domain).decode('ascii')
                if idna_encoded != from_domain:
                    result['is_misspelled'] = True
                    result['suspicious_domain'] = from_domain
                    result['idna_encoded'] = idna_encoded
            except:
                pass
        
        return result
    
    def _get_domain_age_info(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Get information about domain age (to be enriched with threat intel)"""
        from_domain = self._extract_sender_domain(headers)
        return {
            'domain': from_domain,
            'is_new_domain': None,  # Will be populated by threat intel
            'registration_date': None,
            'age_days': None
        }
    
    def _analyze_send_time(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze if email was sent at unusual times"""
        date_header = headers.get('Date', '')
        result = {
            'send_time': None,
            'is_unusual_time': False,
            'warning': None
        }
        
        if date_header:
            try:
                # Parse the date from header
                from email.utils import parsedate_to_datetime
                send_time = parsedate_to_datetime(date_header)
                result['send_time'] = send_time.isoformat()
                
                # Check if it's outside business hours (9 AM to 5 PM)
                hour = send_time.hour
                if hour < 9 or hour > 17:
                    result['is_unusual_time'] = True
                    result['warning'] = f"Email sent outside business hours: {hour}:00"
            
            except Exception as e:
                result['warning'] = f"Could not parse date: {str(e)}"
        
        return result