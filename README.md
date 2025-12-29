# GuardKit

Educational Flask app with small security tools:
- Network port scanner
- HTTP header analyzer
- File hash generator (optional VirusTotal integration)
- Fernet encrypt/decrypt
- File metadata + hex preview
- Simple user accounts & report storage (SQLite)

## Setup

1. Create venv and install dependencies:
```bash
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate
pip install -r requirements.txt
