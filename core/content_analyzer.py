import re
from bs4 import BeautifulSoup
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set, Tuple, Any
import tldextract
import base64
from langdetect import detect, LangDetectException

class ContentAnalyzer:
    def __init__(self):
        self.tld_extract = tldextract.TLDExtract(cache_dir=False)
        
        # Enhanced keyword lists
        self.urgency_keywords = [
            'urgent', 'immediate', 'action required', 'required immediately',
            'within 24 hours', 'last chance', 'final warning', 'account suspended',
            'security alert', 'verify your account', 'limited time', 'expiring soon',
            'Unusual activity detected','Your account will be suspended','Act Now'
        ]
        
        self.too_good_keywords = [
            'you have won', 'claim your prize', 'congratulations', 'you are selected',
            'free gift', 'exclusive offer', 'special promotion', 'reward claim',
            'lottery winner', 'inheritance', 'unclaimed money'
        ]
        
        self.fake_alert_keywords = [
            'payment failed', 'suspicious activity', 'login attempt', 'unauthorized access',
            'account compromised', 'security breach', 'invoice attached', 'purchase confirmation',
            'shipping notification', 'delivery problem', 'subscription renewal'
        ]
        
        self.sensitive_info_keywords = [
            'password', 'social security', 'ssn', 'credit card', 'debit card',
            'bank account', 'routing number', 'otp', 'one-time password',
            'verification code', 'pin', 'personal identification number'
        ]
        
        self.generic_greetings = [
            'dear user', 'dear customer', 'dear member', 'dear account holder',
            'dear valued customer', 'dear client', 'dear sir/madam'
        ]
        
        # Keep the original suspicious keywords for backward compatibility
        self.suspicious_keywords = (
            self.urgency_keywords + 
            self.too_good_keywords + 
            self.fake_alert_keywords + 
            self.sensitive_info_keywords
        )
    
    def analyze_content(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email content for phishing indicators"""
        body = email_data.get('body', {})
        text_content = body.get('text', '')
        html_content = body.get('html', '')
        subject = email_data.get('subject', '')
        
        analysis = {
            'urls': self._extract_urls(text_content, html_content),
            'suspicious_keywords': self._find_suspicious_keywords(text_content),
            'language_analysis': self._analyze_language(text_content),
            'formatting_analysis': self._analyze_formatting(html_content),
            'domain_mismatch': self._check_domain_mismatch(email_data),
            'hidden_text': self._find_hidden_text(html_content),
            'subject_analysis': self._analyze_subject(subject),
            'greeting_analysis': self._analyze_greeting(text_content, html_content),
            'sensitive_info_requests': self._find_sensitive_info_requests(text_content),
            'base64_content': self._find_base64_content(text_content, html_content),
            'embedded_forms': self._find_embedded_forms(html_content),
            'tracking_pixels': self._find_tracking_pixels(html_content)
            # New detection features, more features should be added later during project expansion
            # only if necessary, maybe i will add 
        }
        
        return analysis
    
    def _extract_urls(self, text_content: str, html_content: str) -> List[Dict]:
        """Extract URLs from email content"""
        urls = set()
        
        # Extract from text content
        text_urls = re.findall(r'https?://[^\s<>"\']+', text_content)
        urls.update(text_urls)
        
        # Extract from HTML content
        if html_content:
            soup = BeautifulSoup(html_content, 'lxml')
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href.startswith('http'):
                    urls.add(href)
            
            # Also find URLs in other tags
            for tag in soup.find_all(['img', 'script', 'iframe', 'form']):
                for attr in ['src', 'action']:
                    if tag.get(attr) and tag.get(attr).startswith('http'):
                        urls.add(tag.get(attr))
        
        # Analyze each URL
        analyzed_urls = []
        for url in urls:
            analyzed_urls.append(self._analyze_url(url))
        
        return analyzed_urls
    
    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL for suspicious characteristics"""
        parsed = urlparse(url)
        domain_info = self.tld_extract(parsed.netloc)
        
        analysis = {
            'url': url,
            'domain': parsed.netloc,
            'registered_domain': f"{domain_info.domain}.{domain_info.suffix}",
            'path': parsed.path,
            'query': parsed.query,
            'is_ip': self._is_ip_address(parsed.netloc),
            'is_shortened': self._is_shortened_url(url),
            'suspicious_tld': self._is_suspicious_tld(domain_info.suffix),
            'subdomain_count': len([sd for sd in domain_info.subdomain.split('.') if sd]) if domain_info.subdomain else 0
        }
        
        return analysis
    
    def _is_ip_address(self, netloc: str) -> bool:
        """Check if netloc is an IP address"""
        try:
            ipaddress.ip_address(netloc)
            return True
        except ValueError:
            return False
    
    def _is_shortened_url(self, url: str) -> bool:
        """Check if URL is from a known URL shortener"""
        shorteners = {
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly',
            'adf.ly', 'sh.st', 'bc.vc', 'bit.do', 'mcaf.ee', 'su.pr', 'clicky.me'
        }
        
        domain = urlparse(url).netloc.lower()
        return any(shortener in domain for shortener in shorteners)
    
    def _is_suspicious_tld(self, tld: str) -> bool:
        """Check if TLD is suspicious"""
        suspicious_tlds = {
            'xyz', 'top', 'loan', 'win', 'club', 'site', 'online', 'space',
            'tech', 'website', 'stream', 'download', 'gq', 'cf', 'ml', 'ga'
        }
        return tld.lower() in suspicious_tlds
    
    def _find_suspicious_keywords(self, text: str) -> List[Dict]:
        """Find suspicious keywords in text content"""
        found_keywords = []
        text_lower = text.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in text_lower:
                # Find context around the keyword
                context_start = max(0, text_lower.find(keyword) - 20)
                context_end = min(len(text), text_lower.find(keyword) + len(keyword) + 20)
                context = text[context_start:context_end].strip()
                
                found_keywords.append({
                    'keyword': keyword,
                    'context': context,
                    'category': self._categorize_keyword(keyword)
                })
        
        return found_keywords
    
    def _categorize_keyword(self, keyword: str) -> str:
        """Categorize a keyword based on which list it belongs to"""
        if keyword in self.urgency_keywords:
            return 'urgency'
        elif keyword in self.too_good_keywords:
            return 'too_good_to_be_true'
        elif keyword in self.fake_alert_keywords:
            return 'fake_alert'
        elif keyword in self.sensitive_info_keywords:
            return 'sensitive_info_request'
        else:
            return 'other'
    
    def _analyze_language(self, text: str) -> Dict[str, Any]:
        """Analyze language characteristics"""
        # Simple language analysis - could be enhanced with NLP
        analysis = {
            'has_grammar_errors': self._check_grammar_errors(text),
            'has_urgent_language': self._check_urgent_language(text),
            'has_unicode_homoglyphs': self._check_unicode_homoglyphs(text),
            'readability_score': self._calculate_readability(text),
            # New language analysis
            'language_mismatch': self._check_language_mismatch(text)
        }
        return analysis
    
    def _check_grammar_errors(self, text: str) -> bool:
        """Simple grammar error check"""
        # This is a very basic implementation
        common_errors = [
            r'\byour\s+[a-z]+\s+is\b',  # "your account is"
            r'\bclick\s+here\b',        # "click here"
            r'\bverify\s+your\b',       # "verify your"
            r'\bsecurity\s+alert\b',    # "security alert"
        ]
        
        for pattern in common_errors:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _check_urgent_language(self, text: str) -> bool:
        """Check for urgent language"""
        urgent_patterns = [
            r'immediate\s+action', r'urgent', r'required\s+immediately',
            r'within\s+24\s+hours', r'last\s+chance', r'final\s+warning'
        ]
        
        for pattern in urgent_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _check_unicode_homoglyphs(self, text: str) -> bool:
        """Check for Unicode homoglyphs used to spoof domains"""
        # This is a simplified check
        homoglyph_patterns = [
            r'[а-я]',  # Cyrillic characters
            r'[α-ω]',  # Greek characters
        ]
        
        for pattern in homoglyph_patterns:
            if re.search(pattern, text):
                return True
        
        return False
    
    def _calculate_readability(self, text: str) -> float:
        """Calculate a simple readability score"""
        if not text:
            return 0
        
        # Simple Flesch reading ease approximation
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        
        if not words or not sentences:
            return 0
        
        avg_sentence_length = len(words) / len(sentences)
        avg_word_length = sum(len(word) for word in words) / len(words)
        
        # Simplified score (higher is easier to read)
        readability = 206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_word_length)
        return max(0, min(100, readability))
    
    def _analyze_formatting(self, html_content: str) -> Dict[str, Any]:
        """Analyze HTML formatting for suspicious patterns"""
        if not html_content:
            return {}
        
        soup = BeautifulSoup(html_content, 'lxml')
        analysis = {
            'hidden_elements': self._find_hidden_elements(soup),
            'link_text_mismatch': self._find_link_text_mismatch(soup),
            'suspicious_forms': self._find_suspicious_forms(soup),
            'external_resources': self._find_external_resources(soup)
        }
        
        return analysis
    
    def _find_hidden_elements(self, soup) -> List[Dict]:
        """Find hidden elements in HTML"""
        hidden_elements = []
        
        # Elements with display: none or visibility: hidden
        for tag in soup.find_all(style=re.compile(r'(display:\s*none|visibility:\s*hidden)')):
            hidden_elements.append({
                'tag': tag.name,
                'content': tag.get_text(strip=True)[:100] + '...' if tag.get_text(strip=True) else ''
            })
        
        # Hidden input fields
        for input_tag in soup.find_all('input', type='hidden'):
            hidden_elements.append({
                'tag': 'input',
                'name': input_tag.get('name', ''),
                'value': input_tag.get('value', '')[:50]
            })
        
        return hidden_elements
    
    def _find_link_text_mismatch(self, soup) -> List[Dict]:
        """Find links where text doesn't match URL"""
        mismatches = []
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            text = link.get_text(strip=True)
            
            if href.startswith('http') and text:
                # Extract domain from href
                href_domain = urlparse(href).netloc.lower()
                
                # Check if text appears to be a URL but doesn't match
                if re.match(r'https?://', text):
                    text_domain = urlparse(text).netloc.lower()
                    if href_domain != text_domain:
                        mismatches.append({
                            'text': text,
                            'href': href,
                            'text_domain': text_domain,
                            'href_domain': href_domain
                        })
                # Check if text looks like a domain but doesn't match
                elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', text):
                    if href_domain != text.lower():
                        mismatches.append({
                            'text': text,
                            'href': href,
                            'text_domain': text.lower(),
                            'href_domain': href_domain
                        })
        
        return mismatches
    
    def _find_suspicious_forms(self, soup) -> List[Dict]:
        """Find suspicious forms in HTML"""
        suspicious_forms = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Check for forms that submit sensitive data via GET
            if method == 'get' and any(field.get('type') in ['password', 'text'] for field in form.find_all('input')):
                suspicious_forms.append({
                    'action': action,
                    'method': method,
                    'reason': 'Sensitive data submitted via GET'
                })
            
            # Check for forms that submit to external domains
            if action.startswith('http'):
                form_domain = urlparse(action).netloc
                # This would need comparison with sender domain
                suspicious_forms.append({
                    'action': action,
                    'method': method,
                    'reason': 'Form submits to external domain'
                })
        
        return suspicious_forms
    
    def _find_external_resources(self, soup) -> List[Dict]:
        """Find external resources loaded in HTML"""
        external_resources = []
        
        for tag in soup.find_all(['img', 'script', 'link', 'iframe'], src=True):
            src = tag.get('src')
            if src.startswith('http'):
                external_resources.append({
                    'tag': tag.name,
                    'src': src
                })
        
        return external_resources
    
    def _check_domain_mismatch(self, email_data: Dict[str, Any]) -> List[Dict]:
        """Check for domain mismatches between links and sender"""
        sender_domain = email_data.get('headers', {}).get('From', '')
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', sender_domain)
        
        if not email_match:
            return []
        
        sender_domain = email_match.group(1)
        urls = self._extract_urls(
            email_data.get('body', {}).get('text', ''),
            email_data.get('body', {}).get('html', '')
        )
        
        mismatches = []
        for url_info in urls:
            url_domain = url_info.get('registered_domain', '')
            if url_domain and url_domain != sender_domain:
                mismatches.append({
                    'sender_domain': sender_domain,
                    'url_domain': url_domain,
                    'url': url_info.get('url', '')
                })
        
        return mismatches
    
    def _find_hidden_text(self, html_content: str) -> List[str]:
        """Find text that's hidden using various techniques"""
        if not html_content:
            return []
        
        soup = BeautifulSoup(html_content, 'lxml')
        hidden_text = []
        
        # Text with color matching background
        for tag in soup.find_all(style=re.compile(r'color:\s*#[0-9a-f]{6};\s*background-color:\s*#[0-9a-f]{6}')):
            text = tag.get_text(strip=True)
            if text:
                hidden_text.append(f"Color matching background: {text[:50]}...")
        
        # Tiny font size
        for tag in soup.find_all(style=re.compile(r'font-size:\s*[0-2]px')):
            text = tag.get_text(strip=True)
            if text:
                hidden_text.append(f"Tiny font size: {text[:50]}...")
        
        # Text positioned off-screen
        for tag in soup.find_all(style=re.compile(r'position:\s*absolute;\s*(left|top):\s*-[0-9]+px')):
            text = tag.get_text(strip=True)
            if text:
                hidden_text.append(f"Off-screen positioning: {text[:50]}...")
        
        return hidden_text
    
    # NEW METHODS FOR ENHANCED DETECTION
    def _analyze_subject(self, subject: str) -> Dict[str, Any]:
        """Analyze email subject for phishing indicators"""
        analysis = {
            'urgency_detected': False,
            'too_good_detected': False,
            'fake_alert_detected': False,
            'keywords_found': []
        }
        
        subject_lower = subject.lower()
        
        # Check for urgency keywords
        for keyword in self.urgency_keywords:
            if keyword in subject_lower:
                analysis['urgency_detected'] = True
                analysis['keywords_found'].append(keyword)
        
        # Check for too-good-to-be-true keywords
        for keyword in self.too_good_keywords:
            if keyword in subject_lower:
                analysis['too_good_detected'] = True
                analysis['keywords_found'].append(keyword)
        
        # Check for fake alert keywords
        for keyword in self.fake_alert_keywords:
            if keyword in subject_lower:
                analysis['fake_alert_detected'] = True
                analysis['keywords_found'].append(keyword)
        
        return analysis
    
    def _analyze_greeting(self, text_content: str, html_content: str) -> Dict[str, Any]:
        """Analyze email greeting for generic patterns"""
        analysis = {
            'is_generic': False,
            'greeting_found': None,
            'is_personalized': False
        }
        
        # Extract text from HTML if needed
        content = text_content.lower()
        if not content and html_content:
            soup = BeautifulSoup(html_content, 'lxml')
            content = soup.get_text().lower()
        
        # Check for generic greetings
        for greeting in self.generic_greetings:
            if greeting in content:
                analysis['is_generic'] = True
                analysis['greeting_found'] = greeting
                break
        
        # Check for personalized greetings (presence of name)
        # This is a simple check - in a real system, you might use NER
        name_indicators = ['dear mr.', 'dear mrs.', 'dear ms.', 'dear dr.']
        for indicator in name_indicators:
            if indicator in content:
                analysis['is_personalized'] = True
                break
        
        return analysis
    
    def _find_sensitive_info_requests(self, text_content: str) -> Dict[str, Any]:
        """Find requests for sensitive information"""
        analysis = {
            'sensitive_request_detected': False,
            'keywords_found': [],
            'context_examples': []
        }
        
        content_lower = text_content.lower()
        
        for keyword in self.sensitive_info_keywords:
            if keyword in content_lower:
                analysis['sensitive_request_detected'] = True
                analysis['keywords_found'].append(keyword)
                
                # Find context around the keyword
                keyword_index = content_lower.find(keyword)
                if keyword_index != -1:
                    start = max(0, keyword_index - 50)
                    end = min(len(content_lower), keyword_index + len(keyword) + 50)
                    context = text_content[start:end].strip()
                    analysis['context_examples'].append(context)
        
        return analysis
    
    def _find_base64_content(self, text_content: str, html_content: str) -> Dict[str, Any]:
        """Find Base64 encoded content in email"""
        analysis = {
            'base64_detected': False,
            'encoded_blocks': []
        }
        
        # Check text content
        base64_pattern = r'[A-Za-z0-9+/=]{20,}'
        text_matches = re.findall(base64_pattern, text_content)
        
        # Check HTML content
        html_matches = []
        if html_content:
            html_matches = re.findall(base64_pattern, html_content)
        
        all_matches = text_matches + html_matches
        
        for match in all_matches:
            if len(match) >= 20 and not match.isalpha() and not match.isdigit():
                analysis['base64_detected'] = True
                analysis['encoded_blocks'].append(match[:100] + '...' if len(match) > 100 else match)
        
        return analysis
    
    def _find_embedded_forms(self, html_content: str) -> Dict[str, Any]:
        """Find embedded forms in HTML content"""
        analysis = {
            'embedded_forms_detected': False,
            'form_details': []
        }
        
        if not html_content:
            return analysis
        
        soup = BeautifulSoup(html_content, 'lxml')
        forms = soup.find_all('form')
        
        if forms:
            analysis['embedded_forms_detected'] = True
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                input_fields = []
                
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name', '')
                    input_fields.append({
                        'type': input_type,
                        'name': input_name
                    })
                
                analysis['form_details'].append({
                    'action': form_action,
                    'method': form_method,
                    'input_fields': input_fields
                })
        
        return analysis
    
    def _find_tracking_pixels(self, html_content: str) -> Dict[str, Any]:
        """Find tracking pixels in HTML content"""
        analysis = {
            'tracking_pixels_detected': False,
            'pixel_details': []
        }
        
        if not html_content:
            return analysis
        
        soup = BeautifulSoup(html_content, 'lxml')
        images = soup.find_all('img')
        
        for img in images:
            src = img.get('src', '')
            style = img.get('style', '')
            width = img.get('width', '')
            height = img.get('height', '')
            
            # Check for common tracking pixel characteristics, it can sometimes be use for tracking 
            # if an email was opened or not
            is_tracking_pixel = (
                (src and ('pixel' in src.lower() or 'track' in src.lower())) or
                (style and ('display:none' in style or 'visibility:hidden' in style)) or
                (width and height and (width == '1' or height == '1' or width == '0' or height == '0'))
            )
            
            if is_tracking_pixel:
                analysis['tracking_pixels_detected'] = True
                analysis['pixel_details'].append({
                    'src': src,
                    'style': style,
                    'width': width,
                    'height': height
                })
        
        return analysis
    
    def _check_language_mismatch(self, text: str) -> Dict[str, Any]:
        """Check for language mismatches (e.g., German organization sending English email)"""
        analysis = {
            'language_detected': None,
            'potential_mismatch': False,
            'warning': None
        }
        
        if not text.strip():
            return analysis
        
        try:
            # Detect language
            detected_lang = detect(text)
            analysis['language_detected'] = detected_lang
            
            # In a future implementation, i have to update this to you compare with sender's claimed location
            # but this is a simplified version of the implementation
            if detected_lang not in ['en', 'es', 'fr', 'de']:  # Common languages
                analysis['potential_mismatch'] = True
                analysis['warning'] = f"Uncommon language detected: {detected_lang}"
        
        except LangDetectException:
            analysis['warning'] = "Could not detect language"
        
        return analysis