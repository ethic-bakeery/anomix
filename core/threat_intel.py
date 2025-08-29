import requests
import json
import time
from typing import Dict, List, Any, Optional
import yaml
import os

class ThreatIntelligence:
    def __init__(self, config_path: str = 'config/api_keys.yaml'):
        self.config_path = config_path
        self.api_keys = self._load_api_keys()
        self.cache = {}  # Simple cache to avoid duplicate requests
    
    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from configuration file"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        return {}
    
    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Enrich IP address with threat intelligence"""
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        results = {
            'virustotal': self._check_virustotal_ip(ip_address),
            'abuseipdb': self._check_abuseipdb(ip_address),
            'greynoise': self._check_greynoise(ip_address),
            'geoip': self._get_geoip(ip_address)
        }
        
        self.cache[ip_address] = results
        return results
    
    def enrich_url(self, url: str) -> Dict[str, Any]:
        """Enrich URL with threat intelligence"""
        if url in self.cache:
            return self.cache[url]
        
        results = {
            'virustotal': self._check_virustotal_url(url),
            'urlhaus': self._check_urlhaus(url),
            'phishtank': self._check_phishtank(url)
        }
        
        self.cache[url] = results
        return results
    
    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with threat intelligence"""
        if domain in self.cache:
            return self.cache[domain]
        
        results = {
            'virustotal': self._check_virustotal_domain(domain),
            'whois': self._get_whois(domain),
            'domain_age': self._get_domain_age(domain)
        }
        
        self.cache[domain] = results
        return results
    
    def enrich_hash(self, file_hash: str, hash_type: str = 'sha256') -> Dict[str, Any]:
        """Enrich file hash with threat intelligence"""
        cache_key = f"{hash_type}:{file_hash}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        results = {
            'virustotal': self._check_virustotal_file(file_hash, hash_type)
        }
        
        self.cache[cache_key] = results
        return results
    
    def _check_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation with VirusTotal"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {'x-apikey': api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_virustotal_url(self, url: str) -> Dict[str, Any]:
        """Check URL reputation with VirusTotal"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        # URL needs to be encoded for the API
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        api_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        headers = {'x-apikey': api_key}
        
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation with VirusTotal"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {'x-apikey': api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_virustotal_file(self, file_hash: str, hash_type: str) -> Dict[str, Any]:
        """Check file hash reputation with VirusTotal"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation with AbuseIPDB"""
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            return {'error': 'AbuseIPDB API key not configured'}
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                result = data.get('data', {})
                return {
                    'abuse_confidence_score': result.get('abuseConfidenceScore', 0),
                    'total_reports': result.get('totalReports', 0),
                    'country': result.get('countryCode', ''),
                    'isp': result.get('isp', ''),
                    'usage_type': result.get('usageType', '')
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_greynoise(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation with GreyNoise"""
        api_key = self.api_keys.get('greynoise')
        if not api_key:
            return {'error': 'GreyNoise API key not configured'}
        
        url = f'https://api.greynoise.io/v3/community/{ip}'
        headers = {
            'key': api_key,
            'Accept': 'application/json'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'classification': data.get('classification', 'unknown'),
                    'riot': data.get('riot', False),
                    'noise': data.get('noise', False),
                    'name': data.get('name', '')
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _get_geoip(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for IP"""
        # Using free ip-api.com service
        url = f'http://ip-api.com/json/{ip}'
        
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'zip': data.get('zip', ''),
                        'lat': data.get('lat', ''),
                        'lon': data.get('lon', ''),
                        'isp': data.get('isp', ''),
                        'org': data.get('org', ''),
                        'as': data.get('as', '')
                    }
            return {'error': 'GeoIP lookup failed'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_urlhaus(self, url: str) -> Dict[str, Any]:
        """Check URL against URLhaus database"""
        # URLhaus API endpoint
        api_url = 'https://urlhaus-api.abuse.ch/v1/url/'
        
        try:
            response = requests.post(api_url, data={'url': url}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'threat': data.get('threat', ''),
                        'tags': data.get('tags', []),
                        'date_added': data.get('date_added', ''),
                        'blacklists': data.get('blacklists', {})
                    }
                else:
                    return {'status': 'not_found'}
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_phishtank(self, url: str) -> Dict[str, Any]:
        """Check URL against PhishTank database"""
        # PhishTank API endpoint
        api_url = 'http://checkurl.phishtank.com/checkurl/'
        
        try:
            # PhishTank requires the URL to be encoded in a specific way
            import urllib.parse
            encoded_url = urllib.parse.quote_plus(url)
            response = requests.post(api_url, 
                                   data={'url': encoded_url, 'format': 'json'}, 
                                   headers={'User-Agent': 'PhishingEmailAnalyzer/1.0'},
                                   timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                result = data.get('results', {})
                return {
                    'in_database': result.get('in_database', False),
                    'verified': result.get('verified', False),
                    'verified_at': result.get('verified_at', '')
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _get_whois(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain"""
        try:
            import whois
            domain_info = whois.whois(domain)
            
            return {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers': list(domain_info.name_servers) if domain_info.name_servers else [],
                'emails': domain_info.emails if hasattr(domain_info, 'emails') else []
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_domain_age(self, domain: str) -> Optional[int]:
        """Calculate domain age in days"""
        try:
            import whois
            from datetime import datetime
            
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                if creation_date:
                    age_days = (datetime.now() - creation_date).days
                    return age_days
            return None
        except:
            return None