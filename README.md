# PhishGuard

PhishGuard is a Flask-based scam and phishing screening website.

## Current features

- URL risk screening using structural heuristics
- Email text screening
- SMS/WhatsApp/message screening
- Call transcript screening
- 0–100 risk score with explanations
- URLs found inside emails/messages/transcripts are analyzed too
- Responsive web interface
- `/api/health` endpoint for a simple health check

## Important limitation

This version is a **heuristic prototype**. It does not prove that a URL, sender, email, caller, or website is safe or malicious. It does not visit submitted URLs, query a threat-intelligence provider, or transcribe audio.

## Run on Windows

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Development roadmap

### Phase 1 — Working MVP
- URL, email, message and call-transcript scanners
- Risk score and explanations
- Clean responsive interface

### Phase 2 — Threat intelligence
- Optional Google Safe Browsing / VirusTotal integration
- DNS/domain age and certificate information where legally and technically appropriate
- Reputation results shown separately from heuristic results

### Phase 3 — Machine learning + voice
- Train an NLP classifier on labeled scam/phishing text
- Add speech-to-text for uploaded call recordings
- Combine model probability with rule-based signals

### Phase 4 — Production hardening
- Authentication and scan history
- Rate limiting and input-size limits
- Secure logging and privacy controls
- Deployment with production WSGI server


## URL risk bands

- 0-34: No obvious threats
- 35-59: Suspicious
- 60-79: High risk
- 80-100: Very high risk

The score is heuristic and does not prove that a URL is safe or malicious. PhishGuard does not visit the submitted URL during this local analysis.


## Optional real-time threat intelligence

PhishGuard can optionally query Google Safe Browsing before returning the URL result. Google documents `urls.search` as a real-time URL check against its constantly updated unsafe-resource lists. The raw URL is sent to Google when this integration is enabled. Safe Browsing is intended for non-commercial use; commercial use should use Google's Web Risk product instead.

### Configure the API key

1. Create/choose a Google Cloud project and enable Safe Browsing.
2. Create an API key.
3. Create a `.env` file in the project root from `.env.example`.
4. Put your key in `GOOGLE_SAFE_BROWSING_API_KEY`.
5. Restart Flask.

For a quick Windows PowerShell test without a `.env` file:

```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="YOUR_KEY_HERE"
python app.py
```

The browser never receives the API key. If the key is missing or the provider is unavailable, PhishGuard falls back to local heuristics instead of failing the scan.

**Privacy:** because `urls.search` sends the actual URL to Google, do not enable this provider for sensitive/private URLs unless you are comfortable with that disclosure.
