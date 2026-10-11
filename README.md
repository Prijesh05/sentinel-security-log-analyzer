# Sentinel — Python Security Log Analyzer

A beginner-friendly Flask web application with a dark cybersecurity dashboard. It reads an uploaded `.log`, `.txt`, or `.csv` text file and applies transparent keyword rules to classify events.

## Features
- Dark, responsive dashboard
- Upload a log file (maximum 2 MB)
- Counts for total events, failed logins, high-severity events, and successful logins
- Event distribution chart
- Search and severity filters
- CSV report download
- Built-in demo data
- Basic file extension and size validation

## Requirements
- Python 3.10 or newer
- Internet connection for the Chart.js chart library loaded from a CDN (the rest of the app runs locally)

## Setup on Windows
1. Extract `security_log_analyzer.zip`.
2. Open the extracted `security_log_analyzer` folder.
3. Click the folder address bar in File Explorer, type `cmd`, and press Enter.
4. (Recommended) Create a virtual environment:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```
5. Install packages:
   ```bat
   py -m pip install -r requirements.txt
   ```
6. Start the website:
   ```bat
   py app.py
   ```
7. In a browser, open `http://127.0.0.1:5000`.
8. Click **Load demo data** or upload `sample_logs/security.log`.

## Setup on macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000`.

## Expected log format
The demo uses keyword-based lines such as:
```text
2026-10-11 09:01:12 FAILED LOGIN prijesh
2026-10-11 09:03:02 SUCCESSFUL LOGIN admin
2026-10-11 09:04:15 UNKNOWN USER hacker
2026-10-11 09:05:20 SUSPICIOUS ACCESS admin
```
The parser looks for these phrases (case-insensitively):
- `FAILED LOGIN` or `LOGIN FAILED`
- `SUCCESSFUL LOGIN`, `LOGIN SUCCESS`, or `LOGIN SUCCESSFUL`
- `UNKNOWN USER` or `INVALID USER`
- `SUSPICIOUS ACCESS` or `UNAUTHORIZED ACCESS`

Three or more failed-login entries for the same final token/user are marked **High** as **Multiple Failed Logins**.

## Important limitations
- This is a classroom prototype, not a production SIEM or intrusion-detection system.
- It analyzes only the file uploaded by a user; it does not monitor a live device or network.
- Keyword rules can miss events or misclassify logs with a different format. High severity means “review this event,” not “confirmed attack.”
- The demo server is for local development only. Do not expose it to the public internet as configured.
- Before real deployment, set a strong secret key, add authentication/CSRF protection, validate log formats, and run behind a production WSGI server.
