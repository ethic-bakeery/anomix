import email
import extract_msg
import os
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List
import magic

class EmailParser:
    def __init__(self):
        self.mime_type_checker = magic.Magic(mime=True)
    
    def parse_email(self, file_path: str) -> Dict[str, Any]:
        """Parse email file and extract structured data"""
        if file_path.endswith('.msg'):
            return self._parse_msg(file_path)
        else:
            return self._parse_eml(file_path)
    
    def _parse_eml(self, file_path: str) -> Dict[str, Any]:
        """Parse EML file"""
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        return self._extract_email_data(msg)
    
    def _parse_msg(self, file_path: str) -> Dict[str, Any]:
        """Parse Outlook MSG file"""
        msg = extract_msg.Message(file_path)
        email_data = {
            'subject': msg.subject,
            'from': msg.sender,
            'to': msg.to,
            'cc': msg.cc,
            'bcc': msg.bcc,
            'date': msg.date,
            'body': msg.body,
            'headers': dict(msg.headerDict) if hasattr(msg, 'headerDict') else {}
        }
        msg.close()
        return email_data
    
    def _extract_email_data(self, msg) -> Dict[str, Any]:
        """Extract data from email message object"""
        # Extract headers
        headers = dict(msg.items())
        
        # Extract body content
        body_content = self._extract_body(msg)
        
        # Extract attachments
        attachments = self._extract_attachments(msg)
        
        return {
            'headers': headers,
            'subject': msg.get('subject', ''),
            'from': msg.get('from', ''),
            'to': msg.get('to', ''),
            'cc': msg.get('cc', ''),
            'bcc': msg.get('bcc', ''),
            'date': msg.get('date', ''),
            'body': body_content,
            'attachments': attachments
        }
    
    def _extract_body(self, msg) -> Dict[str, str]:
        """Extract text and HTML content from email"""
        text_content = ""
        html_content = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" not in content_disposition:
                    if content_type == "text/plain":
                        text_content += part.get_payload(decode=True).decode(
                            part.get_content_charset() or 'utf-8', errors='ignore'
                        )
                    elif content_type == "text/html":
                        html_content += part.get_payload(decode=True).decode(
                            part.get_content_charset() or 'utf-8', errors='ignore'
                        )
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                text_content = msg.get_payload(decode=True).decode(
                    msg.get_content_charset() or 'utf-8', errors='ignore'
                )
            elif content_type == "text/html":
                html_content = msg.get_payload(decode=True).decode(
                    msg.get_content_charset() or 'utf-8', errors='ignore'
                )
        
        return {'text': text_content, 'html': html_content}
    
    def _extract_attachments(self, msg) -> List[Dict]:
        """Extract attachments from email"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        payload = part.get_payload(decode=True)
                        file_data = {
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(payload),
                            'payload': payload
                        }
                        attachments.append(file_data)
        
        return attachments