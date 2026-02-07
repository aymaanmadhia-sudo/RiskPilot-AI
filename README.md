# RiskPilot AI

AI-powered Cyber Risk Intelligence Platform that analyzes real-world vulnerabilities using CVE data and AI.

## Features
- Live CVE vulnerability analysis (NVD API)
- CVSS-based risk scoring
- OWASP risk mapping
- Human-in-the-loop validation
- AI-generated threat insights

## Setup

1. Clone repo
2. Install requirements:
   pip install -r requirements.txt
3. Create .env file with:
   GEMINI_API_KEY=your_key
   NVD_API_KEY=your_key
4. Run:
   streamlit run app.py

## Built With
Python, Streamlit, Gemini API, NVD API
