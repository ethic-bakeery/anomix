#!/usr/bin/env python3
import os
import glob
import json
from core.email_parser import EmailParser
from core.header_analyzer import HeaderAnalyzer
from core.content_analyzer import ContentAnalyzer
from core.attachment_analyzer import AttachmentAnalyzer
from core.risk_scorer import RiskScorer

def analyze_email(file_path, output_dir=None):
    """Analyze a single email file and optionally save results"""
    # Initialize components
    email_parser = EmailParser()
    header_analyzer = HeaderAnalyzer()
    content_analyzer = ContentAnalyzer()
    attachment_analyzer = AttachmentAnalyzer()
    risk_scorer = RiskScorer()
    
    # Parse email
    email_data = email_parser.parse_email(file_path)
    
    # Analyze headers
    header_analysis = header_analyzer.analyze_headers(email_data.get('headers', {}))
    
    # Analyze content
    content_analysis = content_analyzer.analyze_content(email_data)
    
    # Analyze attachments
    attachment_analysis = attachment_analyzer.analyze_attachments(email_data.get('attachments', []))
    
    # Calculate risk score
    all_results = {
        'email_data': email_data,
        'header_analysis': header_analysis,
        'content_analysis': content_analysis,
        'attachment_analysis': attachment_analysis,
        'threat_intel': {}  # Skip threat intel for training
    }
    
    risk_assessment = risk_scorer.calculate_risk_score(all_results)
    all_results['risk_assessment'] = risk_assessment
    
    # Save results if output directory is provided
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        filename = os.path.splitext(os.path.basename(file_path))[0] + '.json'
        output_path = os.path.join(output_dir, filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        
        print(f"Saved analysis to: {output_path}")
    
    return all_results

def train_model():
    """Train the machine learning model on sample emails"""
    
    # Create analysis results directories if they don't exist
    os.makedirs('samples/phishing/analysis_results', exist_ok=True)
    os.makedirs('samples/legitimate/analysis_results', exist_ok=True)
    
    # Analyze phishing samples
    print("Analyzing phishing samples...")
    for ext in ['eml', 'msg']:
        for file in glob.glob(f'samples/phishing/*.{ext}'):
            print(f"Processing {file}...")
            try:
                analyze_email(file, output_dir='samples/phishing/analysis_results')
            except Exception as e:
                print(f"Error processing {file}: {e}")
    
    # Analyze legitimate samples
    print("Analyzing legitimate samples...")
    for ext in ['eml', 'msg']:
        for file in glob.glob(f'samples/legitimate/*.{ext}'):
            print(f"Processing {file}...")
            try:
                analyze_email(file, output_dir='samples/legitimate/analysis_results')
            except Exception as e:
                print(f"Error processing {file}: {e}")
    
    # Check if JSON files were created
    phishing_json_files = glob.glob('samples/phishing/analysis_results/*.json')
    legitimate_json_files = glob.glob('samples/legitimate/analysis_results/*.json')
    
    print(f"Found {len(phishing_json_files)} phishing JSON files")
    print(f"Found {len(legitimate_json_files)} legitimate JSON files")
    
    # Train the model
    print("Training the model...")
    from models.train_model import train_phishing_model
    success = train_phishing_model('samples', 'models/phishing_model.pkl')
    
    if success:
        print("Model trained successfully!")
    else:
        print("Model training failed.")

if __name__ == '__main__':
    train_model()
