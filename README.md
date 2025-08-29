# **Anomix - Advanced Phishing Email Analyzer**

https://img.shields.io/badge/Anomix-Phishing%2520Analyzer-blue

https://img.shields.io/badge/Python-3.8%252B-green

https://img.shields.io/badge/License-MIT-orange

Anomix is a comprehensive CLI-based phishing email analysis tool that automates email investigation by extracting artifacts (headers, URLs, attachments), enriching them with Threat Intelligence (TI) sources, and generating a risk score & incident report.

## **Features**

### **Core Analysis Components**

- **Email Ingestion**: Supports .eml and .msg formats
- **Header Analysis**: SPF/DKIM/DMARC validation, sender/reply-to domain analysis
- **Content Analysis**: URL extraction, suspicious keyword detection, language analysis
- **Attachment Analysis**: File type detection, macro analysis, threat assessment
- **Threat Intelligence Integration**: VirusTotal, AbuseIPDB, GreyNoise, URLhaus, PhishTank
- **Risk Scoring Engine**: Quantitative risk assessment with detailed breakdown
- **Multi-format Reporting**: JSON, HTML, and PDF reports
- **Machine Learning**: Trainable phishing detection model

### **Advanced Detection Capabilities**

Anomix detects over 50 different phishing indicators across these categories:

### **Header & Sender Analysis**

- Sender domain mismatches and lookalike domains
- Free email services used for official communication
- SPF/DKIM/DMARC authentication failures
- Suspicious sending IPs and newly registered domains
- Unusual send times (outside business hours)
- Message-ID domain mismatches

### **Subject Line Analysis**

- Urgency/fear language ("Act Now", "Account Locked")
- Too-good-to-be-true offers ("You've won", "Claim prize")
- Fake alerts ("Payment failed", "Security notice")

### **Email Body Analysis**

- Poor grammar and unusual sentence structures
- Generic greetings ("Dear Customer" vs personalized)
- Sensitive information requests (passwords, SSN, credit cards)
- Hidden text, base64-encoded content, abnormal spacing
- Embedded HTML forms and scripts
- Language mismatches (e.g., German org sending English email)

### **URL & Link Analysis**

- Mismatched hyperlinks (display text ≠ actual URL)
- Obfuscated/shortened URLs (bit.ly, tinyurl)
- Suspicious long or encoded strings in links
- HTTPS lookalikes (secure-login.com.bank.example.com)
- Homograph attacks using Unicode characters
- IP-based URLs instead of domains
- Suspicious TLDs (.xyz, .top, .loan, .win)

### **Attachment Analysis**

- Suspicious extensions (.exe, .scr, .bat, .js, .vbs, .docm)
- Unexpected invoices/delivery notices (FedEx, DHL, UPS)
- Password-protected or encrypted attachments
- Office documents with macros
- Packed executables
- Scripts with suspicious patterns

### **Behavioral Analysis**

- Tracking pixels (tiny hidden images)
- Emails sent to many recipients but pretending to be personal
- Domain age analysis (newly registered domains)

## **Installation**

### **Prerequisites**

- Python 3.8+
- wkhtmltopdf (for PDF report generation)

### **Step-by-Step Installation**

1. **Clone the repository**
    
    ```bash
    git clone https://github.com/ethic-bakeery/anomix.git
    cd anomix
    ```
    
2. **Create a virtual environment**
    
    ```
    python3 -m venv venv
    source venv/bin/activate# On Windows: venv\Scripts\activate
    ```
    
3. **Install dependencies**
    
    ```bash
    pip install -r requirements.txt
    ```
    
4. **Install wkhtmltopdf**
    - Ubuntu/Debian: **`sudo apt-get install wkhtmltopdf`**
    - macOS: **`brew install wkhtmltopdf`**
    - Windows: Download from [wkhtmltopdf.org](https://wkhtmltopdf.org/downloads.html)
5. **Configure API keys**
    
    Create **`config/api_keys.yaml`** with your API keys:
    
    ```yaml
    # VirusTotal API Keyvirustotal: "your_virustotal_api_key_here"
    
    # AbuseIPDB API Keyabuseipdb: "your_abuseipdb_api_key_here"
    
    # GreyNoise API Keygreynoise: "your_greynoise_api_key_here"
    
    # Add other API keys as needed
    ```
    

## **Usage**

### **Analyzing Emails**

```bash
# Basic analysis
python3 anomix.py analyze suspicious_email.eml

# With detailed output and multiple report formats
python3 anomix.py analyze suspicious_email.eml --output reports/ --format all --verbose

# Skip threat intelligence lookups (faster)
python3 anomix.py analyze suspicious_email.eml --no-intel
```

### **Training the Model**

1. **Prepare sample emails**
    
    ```yaml
    samples/
    ├── phishing/
    │   ├── sample1.eml
    │   ├── sample2.msg
    │   └── ...
    └── legitimate/
        ├── email1.eml
        ├── email2.msg
        └── ...
    ```
    
2. **Analyze samples and train model**

The tool consists of:

- **`anomix.py`** - The main CLI interface for analyzing emails
- **`orchestrate_training.py`** - Script to prepare training data and train the model
- **`models/train_model.py`** - Core machine learning training logic
    
    ```python
    # Option 1: Use the orchestrator script
    python3 orchestrate_training.py

    # Option 2: Use the CLI command
    python3 anomix.py train samples/ --output models/phishing_model.pkl
    ```
This will:

1. Analyze all email samples in both directories
2. Extract features from each email
3. Train a Random Forest classifier
4. Save the model to **`models/phishing_model.pkl`**

### **3. Analyze a Suspicious Email**

Use the main tool to analyze a potentially malicious email:

```bash
    # Basic analysis
    python anomix.py analyze suspicious_email.eml

    # Detailed analysis with all report formats
    python anomix.py analyze suspicious_email.eml --output reports/ --format all --verbose

    # Analysis without external API calls (faster)
    python anomix.py analyze suspicious_email.eml --no-intel
```
or  Batch Analysis of Multiple Emails
```bash
for email in suspicious_emails/*.eml; do
    echo "Analyzing $email..."
    python anomix.py analyze "$email" --output batch_results/ --format json
done
```
**The training process**
    - Analyzes all sample emails
    - Extracts features from each email
    - Trains a Random Forest classifier
    - Saves the model to the specified path
    - Outputs model accuracy and classification report

## **Project Structure**

```
anomix/
├── anomix.py                 # Main CLI entry point
├── config/
│   ├── config.yaml          # Configuration file
│   └── api_keys.yaml        # API keys (gitignored)
├── core/
│   ├── __init__.py
│   ├── email_parser.py      # Email parsing functionality
│   ├── header_analyzer.py   # Header analysis
│   ├── content_analyzer.py  # Body content analysis
│   ├── attachment_analyzer.py # Attachment handling
│   ├── threat_intel.py      # Threat intelligence integration
│   ├── risk_scorer.py       # Risk scoring engine
│   └── reporter.py          # Report generation
├── models/
│   ├── __init__.py
│   ├── train_model.py       # Model training script
│   └── phishing_model.pkl   # Trained model (generated)
├── samples/                 # Directory for sample emails
│   ├── phishing/
│   └── legitimate/
├── templates/               # HTML report templates
│   └── report_template.html
├── outputs/                 # Generated reports
│   ├── json/
│   ├── html/
│   └── pdf/
├── requirements.txt         # Python dependencies
└── orchestrate_training.py          
```

## **How It Works**

### **Analysis Pipeline**

1. **Email Parsing**: Extracts headers, body content, and attachments from email files
2. **Header Analysis**: Validates authentication protocols and checks for inconsistencies
3. **Content Analysis**: Examines text and HTML content for phishing indicators
4. **Attachment Analysis**: Inspects files for malicious content
5. **Threat Intelligence Enrichment**: Queries external services for reputation data
6. **Risk Scoring**: Calculates a comprehensive risk score based on all findings
7. **Report Generation**: Creates detailed reports in multiple formats

### **Risk Scoring**

Anomix uses a weighted scoring system with over 20 different risk factors:

- Authentication failures (SPF/DKIM/DMARC): +15 points each
- Newly registered domains (<30 days): +20 points
- Known phishing domains: +40 points
- Malicious files: +50 points
- Malicious URLs: +40 points
- Suspicious keywords: +10 points each
- Header inconsistencies: +15 points each
- And many more...

**Risk Levels:**

- 0-30: Low Risk (likely safe)
- 31-60: Medium Risk (suspicious, needs review)
- 61-100: High Risk (likely phishing)

### **Machine Learning**

The ML model extracts features from emails including:

- Number of URLs and attachments
- Presence of suspicious keywords
- Authentication failures
- Domain mismatches
- Hidden content detection

The model is trained using a Random Forest classifier on labeled samples of phishing and legitimate emails.

## **Sample Output**
![sample output](./pictures/srm-red.PNG)

### **Report Example**

JSON, HTML, and PDF reports include:

- Executive summary with risk score
- Detailed analysis of each component
- Threat intelligence findings
- Risk score breakdown
- Recommendations for action

## **🚀 Expanding Anomix**

### **Adding New Detection Rules**

1. **Header Analysis**: Add methods to **`header_analyzer.py`**
2. **Content Analysis**: Extend **`content_analyzer.py`** with new pattern detection
3. **Attachment Analysis**: Enhance **`attachment_analyzer.py`** with new file type analysis
4. **Risk Scoring**: Update weights and add new factors in **`risk_scorer.py`**

### **Integrating New Threat Intelligence Sources**

1. Add API configuration in **`config/api_keys.yaml`**
2. Implement enrichment methods in **`threat_intel.py`**
3. Update the **`_enrich_with_threat_intel`** method in **`anomix.py`**

### **Adding New Report Formats**

1. Implement new report generation methods in **`reporter.py`**
2. Add support for the new format in the **`generate_report`** method
3. Update CLI options to include the new format

### **Enhancing the Machine Learning Model**

1. Add new feature extraction methods in **`train_model.py`**
2. Experiment with different algorithms in the training process
3. Add more diverse samples to the training dataset

## **Contributing**

We welcome contributions to Anomix! Here's how you can help:

1. Fork the repository
2. Create a feature branch (**`git checkout -b feature/amazing-feature`**)
3. Commit your changes (**`git commit -m 'Add amazing feature'`**)
4. Push to the branch (**`git push origin feature/amazing-feature`**)
5. Open a Pull Request

### **Areas for Contribution**

- Additional threat intelligence integrations
- New detection rules and patterns
- Enhanced machine learning features
- Improved report templates and formatting
- Performance optimizations
- Documentation improvements

## **📞 Support**

If you have questions or need help:
1. Open an [Issue](https://github.com/yourusername/anomix/issues) for bugs or feature requests
2. Email [bakeery](https://mailto:ethic.bakeery@gmail.com/) for direct assistance