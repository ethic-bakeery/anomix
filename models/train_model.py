import os
import pickle
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import json
from pathlib import Path

def extract_features_from_analysis(analysis_results):
    """Extract features from analysis results for ML model"""
    features = {
        'num_urls': len(analysis_results.get('content_analysis', {}).get('urls', [])),
        'num_attachments': len(analysis_results.get('attachment_analysis', {}).get('attachments', [])),
        'has_suspicious_keywords': 1 if analysis_results.get('content_analysis', {}).get('suspicious_keywords', []) else 0,
        'auth_failures': 0,
        'domain_mismatches': len(analysis_results.get('content_analysis', {}).get('domain_mismatch', [])),
        'hidden_content': len(analysis_results.get('content_analysis', {}).get('hidden_text', []))
    }
    
    # Check authentication failures
    auth_results = analysis_results.get('header_analysis', {}).get('authentication_results', {})
    for protocol in ['spf', 'dkim', 'dmarc']:
        if auth_results.get(protocol) == 'fail':
            features['auth_failures'] += 1
    
    return features

def train_phishing_model(samples_dir, output_path):
    """Train a phishing detection model on sample emails"""
    features = []
    labels = []
    
    # Process phishing samples
    phishing_dir = os.path.join(samples_dir, 'phishing', 'analysis_results')
    if os.path.exists(phishing_dir):
        for file in os.listdir(phishing_dir):
            if file.endswith('.json'):
                with open(os.path.join(phishing_dir, file), 'r') as f:
                    analysis = json.load(f)
                    features.append(extract_features_from_analysis(analysis))
                    labels.append(1)  # Phishing
    
    # Process legitimate samples
    legitimate_dir = os.path.join(samples_dir, 'legitimate', 'analysis_results')
    if os.path.exists(legitimate_dir):
        for file in os.listdir(legitimate_dir):
            if file.endswith('.json'):
                with open(os.path.join(legitimate_dir, file), 'r') as f:
                    analysis = json.load(f)
                    features.append(extract_features_from_analysis(analysis))
                    labels.append(0)  # Legitimate
    
    if not features:
        print("No training data found. Ensure samples are organized in phishing/ and legitimate/ subdirectories.")
        print(f"Looked in: {phishing_dir} and {legitimate_dir}")
        # List files in these directories for debugging
        if os.path.exists(phishing_dir):
            print(f"Files in phishing directory: {os.listdir(phishing_dir)}")
        if os.path.exists(legitimate_dir):
            print(f"Files in legitimate directory: {os.listdir(legitimate_dir)}")
        return False
    
    # Convert to DataFrame
    df = pd.DataFrame(features)
    labels = pd.Series(labels)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        df, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Model accuracy: {accuracy:.2f}")
    print("Classification report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Save model
    with open(output_path, 'wb') as f:
        pickle.dump(model, f)
    
    # Save feature names for later use
    feature_info = {
        'feature_names': list(df.columns),
        'model_type': 'random_forest'
    }
    
    with open(output_path.replace('.pkl', '_features.json'), 'w') as f:
        json.dump(feature_info, f)
    
    return True

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python train_model.py <samples_directory> <output_path>")
        sys.exit(1)
    
    train_phishing_model(sys.argv[1], sys.argv[2])