import os
import hashlib
import magic
import tempfile
from typing import Dict, List, Any
import olefile
from oletools.olevba import VBA_Parser
import json
import re

class AttachmentAnalyzer:
    def __init__(self):
        self.mime_type_checker = magic.Magic(mime=True)
        self.suspicious_extensions = {
            'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'vbe', 'js', 'jse',
            'wsf', 'wsh', 'ps1', 'psm1', 'sh', 'bash', 'msi', 'msp', 'gadget',
            'docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam',
            'sldm', 'hta', 'jar', 'app', 'action', 'apk', 'deb', 'rpm', 'scr'
        }
        self.invoice_keywords = [
            'invoice', 'bill', 'payment', 'receipt', 'statement', 'order',
            'purchase', 'confirmation', 'shipping', 'delivery', 'tracking',
            'ups', 'fedex', 'dhl', 'usps', 'airway', 'consignment'
        ]
    
    def analyze_attachments(self, attachments: List[Dict]) -> Dict[str, Any]:
        """Analyze all attachments in an email with enhanced detection"""
        analysis_results = {
            'attachments': [],
            'total_count': len(attachments),
            'malicious_count': 0,
            'suspicious_count': 0,
            # New detection features
            'password_protected_count': 0,
            'invoice_attachment_count': 0
        }
        
        for attachment in attachments:
            attachment_analysis = self._analyze_single_attachment(attachment)
            analysis_results['attachments'].append(attachment_analysis)
            
            # Update counts
            threat_level = attachment_analysis.get('threat_level', 'clean')
            if threat_level == 'malicious':
                analysis_results['malicious_count'] += 1
            elif threat_level == 'suspicious':
                analysis_results['suspicious_count'] += 1
            
            # New count updates
            if attachment_analysis.get('is_password_protected', False):
                analysis_results['password_protected_count'] += 1
            
            if attachment_analysis.get('is_invoice_related', False):
                analysis_results['invoice_attachment_count'] += 1
        
        return analysis_results
    
    def _analyze_single_attachment(self, attachment: Dict) -> Dict[str, Any]:
        """Analyze a single attachment with enhanced detection"""
        filename = attachment.get('filename', 'unknown')
        payload = attachment.get('payload', b'')
        content_type = attachment.get('content_type', 'application/octet-stream')
        
        analysis = {
            'filename': filename,
            'size': len(payload),
            'content_type': content_type,
            'hashes': self._calculate_hashes(payload),
            'file_type': self._determine_file_type(payload, filename),
            'threat_level': 'clean',
            'indicators': [],
            # New detection features
            'is_password_protected': self._check_password_protection(payload, filename),
            'is_invoice_related': self._check_invoice_related(filename),
            'suspicious_extension': self._check_suspicious_extension(filename)
        }
        
        # Additional analysis based on file type
        if analysis['file_type'] == 'office':
            office_analysis = self._analyze_office_document(payload)
            analysis.update(office_analysis)
        
        elif analysis['file_type'] == 'executable':
            exec_analysis = self._analyze_executable(payload, filename)
            analysis.update(exec_analysis)
        
        elif analysis['file_type'] == 'script':
            script_analysis = self._analyze_script(payload, filename)
            analysis.update(script_analysis)
        
        elif analysis['file_type'] == 'archive':
            archive_analysis = self._analyze_archive(payload, filename)
            analysis.update(archive_analysis)
        
        # Determine overall threat level
        analysis['threat_level'] = self._determine_threat_level(analysis)
        
        return analysis
    
    def _calculate_hashes(self, payload: bytes) -> Dict[str, str]:
        """Calculate various hashes for the file"""
        return {
            'md5': hashlib.md5(payload).hexdigest(),
            'sha1': hashlib.sha1(payload).hexdigest(),
            'sha256': hashlib.sha256(payload).hexdigest()
        }
    
    def _determine_file_type(self, payload: bytes, filename: str) -> str:
        """Determine the file type based on content and extension"""
        if not payload:
            return 'unknown'
        
        # Get MIME type from content
        try:
            mime_type = self.mime_type_checker.from_buffer(payload)
        except:
            mime_type = 'application/octet-stream'
        
        # Get file extension
        _, ext = os.path.splitext(filename.lower())
        ext = ext.lstrip('.')
        
        # Categorize file type
        file_type = 'other'
        
        # Office documents
        office_mimes = {
            'application/msword', 'application/vnd.ms-word',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/vnd.oasis.opendocument.text', 'application/vnd.oasis.opendocument.spreadsheet'
        }
        office_exts = {'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods'}
        
        if mime_type in office_mimes or ext in office_exts:
            file_type = 'office'
        
        # Executables
        executable_mimes = {
            'application/x-dosexec', 'application/x-msdownload',
            'application/x-executable', 'application/x-mach-binary'
        }
        executable_exts = {'exe', 'dll', 'sys', 'com', 'bat', 'cmd', 'msi', 'msp'}
        
        if mime_type in executable_mimes or ext in executable_exts:
            file_type = 'executable'
        
        # Scripts
        script_exts = {'js', 'vbs', 'vbe', 'ps1', 'sh', 'bash', 'py', 'rb', 'pl'}
        if ext in script_exts:
            file_type = 'script'
        
        # Archives
        archive_mimes = {
            'application/zip', 'application/x-zip-compressed',
            'application/x-rar-compressed', 'application/x-tar',
            'application/gzip', 'application/x-7z-compressed'
        }
        archive_exts = {'zip', 'rar', '7z', 'tar', 'gz', 'bz2'}
        
        if mime_type in archive_mimes or ext in archive_exts:
            file_type = 'archive'
        
        # PDFs
        if mime_type == 'application/pdf' or ext == 'pdf':
            file_type = 'pdf'
        
        return file_type
    
    def _analyze_office_document(self, payload: bytes) -> Dict[str, Any]:
        """Analyze Office documents for macros and other suspicious content"""
        analysis = {
            'has_macros': False,
            'macro_analysis': {},
            'ole_objects': [],
            'indicators': []
        }
        
        # Create temporary file for analysis
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(payload)
            temp_file.flush()
            
            try:
                # Check for VBA macros
                vba_parser = VBA_Parser(temp_file.name)
                if vba_parser.detect_vba_macros():
                    analysis['has_macros'] = True
                    
                    # Extract macro information
                    macro_analysis = self._analyze_macros(vba_parser)
                    analysis['macro_analysis'] = macro_analysis
                    
                    # Add indicators if suspicious macros found
                    if macro_analysis.get('suspicious_count', 0) > 0:
                        analysis['indicators'].append('Suspicious macros detected')
                
                # Check for OLE objects
                if olefile.isOleFile(temp_file.name):
                    ole_analysis = self._analyze_ole_objects(temp_file.name)
                    analysis['ole_objects'] = ole_analysis
                    
                    if ole_analysis:
                        analysis['indicators'].append('OLE objects found')
                
                vba_parser.close()
                
            except Exception as e:
                analysis['macro_analysis']['error'] = str(e)
            
            finally:
                os.unlink(temp_file.name)
        
        return analysis
    
    def _analyze_macros(self, vba_parser) -> Dict[str, Any]:
        """Analyze VBA macros for suspicious patterns"""
        analysis = {
            'macro_count': 0,
            'suspicious_count': 0,
            'auto_exec_macros': [],
            'suspicious_keywords': [],
            'extracted_code': ''
        }
        
        try:
            # Extract all macros
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                analysis['macro_count'] += 1
                
                # Check for auto-execute macros
                if any(name in vba_filename.lower() for name in ['auto', 'open', 'close', 'start']):
                    analysis['auto_exec_macros'].append(vba_filename)
                
                # Check for suspicious keywords
                suspicious_patterns = [
                    r'shell', r'wscript\.shell', r'exec', r'createobject',
                    r'adodb\.stream', r'filesystemobject', r'getobject',
                    r'kill', r'delete', r'rmdir', r'mkdir',
                    r'regread', r'regwrite', r'sendkeys',
                    r'http', r'ftp', r'tcp', r'udp', r'winhttp',
                    r'chrw', r'asc', r'strreverse', r'eval'
                ]
                
                code_lower = vba_code.lower()
                found_keywords = []
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, code_lower):
                        found_keywords.append(pattern)
                
                if found_keywords:
                    analysis['suspicious_count'] += 1
                    analysis['suspicious_keywords'].extend(found_keywords)
                
                # Collect some code for analysis
                if len(analysis['extracted_code']) < 1000:  # Limit size
                    analysis['extracted_code'] += f"\n\n--- {vba_filename} ---\n{vba_code[:500]}"
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_ole_objects(self, file_path: str) -> List[Dict]:
        """Analyze OLE objects in Office documents"""
        ole_objects = []
        
        try:
            with olefile.OleFileIO(file_path) as ole:
                for entry in ole.listdir():
                    if entry[0].startswith('\x01OLE') or 'ObjectPool' in entry[0]:
                        ole_objects.append({
                            'name': entry[0],
                            'size': ole.get_size(entry[0]) if ole.exists(entry[0]) else 0,
                            'type': 'OLE Object'
                        })
        except:
            pass
        
        return ole_objects
    
    def _analyze_executable(self, payload: bytes, filename: str) -> Dict[str, Any]:
        """Analyze executable files"""
        analysis = {
            'pe_analysis': {},
            'packer_detection': {},
            'indicators': []
        }
        
        # Basic PE analysis (simplified)
        if len(payload) > 64:  # Minimum size for PE header
            try:
                # Check for MZ header (DOS header)
                if payload.startswith(b'MZ'):
                    analysis['pe_analysis']['is_pe'] = True
                    
                    # Check for common packers
                    packer_indicators = [
                        (b'UPX!', 'UPX'),
                        (b'ASPack', 'ASPack'),
                        (b'FSG!', 'FSG'),
                        (b'PECompact', 'PECompact'),
                        (b'Themida', 'Themida'),
                        (b'VMProtect', 'VMProtect')
                    ]
                    
                    for pattern, name in packer_indicators:
                        if pattern in payload:
                            analysis['packer_detection']['detected'] = name
                            analysis['indicators'].append(f'Packed with {name}')
                            break
                
                else:
                    analysis['pe_analysis']['is_pe'] = False
            
            except Exception as e:
                analysis['pe_analysis']['error'] = str(e)
        
        return analysis
    
    def _analyze_script(self, payload: bytes, filename: str) -> Dict[str, Any]:
        """Analyze script files"""
        analysis = {
            'script_analysis': {},
            'suspicious_patterns': [],
            'indicators': []
        }
        
        try:
            content = payload.decode('utf-8', errors='ignore').lower()
            
            # Check for suspicious patterns in scripts
            suspicious_patterns = [
                (r'wscript\.shell', 'WScript.Shell object creation'),
                (r'exec', 'Process execution'),
                (r'createobject', 'COM object creation'),
                (r'adodb\.stream', 'ADODB.Stream for file operations'),
                (r'filesystemobject', 'FileSystemObject access'),
                (r'getobject', 'COM object access'),
                (r'eval\s*\(', 'Dynamic code evaluation'),
                (r'window\.open', 'Browser window opening'),
                (r'document\.write', 'Dynamic content writing'),
                (r'xmlhttprequest', 'HTTP requests'),
                (r'activexobject', 'ActiveX object creation')
            ]
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, content):
                    analysis['suspicious_patterns'].append(description)
            
            if analysis['suspicious_patterns']:
                analysis['indicators'].append('Suspicious script patterns detected')
        
        except Exception as e:
            analysis['script_analysis']['error'] = str(e)
        
        return analysis
    
    def _analyze_archive(self, payload: bytes, filename: str) -> Dict[str, Any]:
        """Analyze archive files"""
        analysis = {
            'archive_analysis': {},
            'contains_executables': False,
            'password_protected': False,
            'indicators': []
        }
        
        # Simple archive analysis
        # In a real implementation, you would extract and analyze contents
        # Future implementation should focus on creating a sandbox that the sample will be analyze
        # I have to complete this within this year 2025
        content_str = str(payload[:200])  # Look at first 200 bytes
        
        # Check for potential password protection indicators
        password_indicators = [
            'encrypted', 'password', 'pkware', 'winzip'
        ]
        
        for indicator in password_indicators:
            if indicator in content_str.lower():
                analysis['password_protected'] = True
                analysis['indicators'].append('Possible password protection')
                break
        
        return analysis
    
    def _determine_threat_level(self, analysis: Dict) -> str:
        """Determine the threat level of an attachment"""
        indicators = analysis.get('indicators', [])
        
        # Office documents with macros
        if analysis.get('file_type') == 'office' and analysis.get('has_macros', False):
            macro_analysis = analysis.get('macro_analysis', {})
            if macro_analysis.get('suspicious_count', 0) > 0:
                return 'malicious'
            elif macro_analysis.get('auto_exec_macros'):
                return 'suspicious'
        
        # Executables with packers
        if analysis.get('file_type') == 'executable' and analysis.get('packer_detection', {}).get('detected'):
            return 'suspicious'
        
        # Scripts with suspicious patterns
        if analysis.get('file_type') == 'script' and analysis.get('suspicious_patterns'):
            return 'suspicious'
        
        # Password protected archives
        if analysis.get('file_type') == 'archive' and analysis.get('password_protected', False):
            return 'suspicious'
        
        # Any other indicators
        if indicators or analysis.get('suspicious_extension', False):
            return 'suspicious'
        
        return 'clean'
    
    # NEW METHODS FOR ENHANCED DETECTION
    def _check_suspicious_extension(self, filename: str) -> bool:
        """Check if file has a suspicious extension"""
        _, ext = os.path.splitext(filename.lower())
        ext = ext.lstrip('.')
        return ext in self.suspicious_extensions
    
    def _check_password_protection(self, payload: bytes, filename: str) -> bool:
        """Check if file appears to be password protected"""
        # Simple heuristic based on file content
        content_str = str(payload[:200])  # Look at first 200 bytes
        
        password_indicators = [
            'encrypted', 'password', 'pkware', 'winzip', 'secure',
            'protected', 'encrypt', 'aes', 'rc4', 'blowfish'
        ]
        
        for indicator in password_indicators:
            if indicator in content_str.lower():
                return True
        
        return False
    
    def _check_invoice_related(self, filename: str) -> bool:
        """Check if filename suggests it's an invoice or delivery notice"""
        filename_lower = filename.lower()
        
        for keyword in self.invoice_keywords:
            if keyword in filename_lower:
                return True
        
        return False