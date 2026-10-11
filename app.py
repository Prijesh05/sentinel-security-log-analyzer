from collections import Counter
from datetime import datetime
from io import BytesIO, StringIO
import csv
import re

from flask import Flask, render_template, request, send_file, flash, redirect, url_for

app = Flask(__name__)
app.secret_key = "replace-this-with-a-random-secret-key"

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB


def classify_line(line):
    """Classify one log line using simple, transparent keyword rules."""
    upper = line.upper()
    user = "-"
    parts = line.strip().split()
    if parts:
        user = parts[-1]

    if "FAILED LOGIN" in upper or "LOGIN FAILED" in upper:
        return {"event": "Failed Login", "severity": "Warning", "user": user}
    if "SUCCESSFUL LOGIN" in upper or "LOGIN SUCCESS" in upper or "LOGIN SUCCESSFUL" in upper:
        return {"event": "Successful Login", "severity": "Normal", "user": user}
    if "UNKNOWN USER" in upper or "INVALID USER" in upper:
        return {"event": "Unknown User", "severity": "High", "user": user}
    if "SUSPICIOUS ACCESS" in upper or "UNAUTHORIZED ACCESS" in upper:
        return {"event": "Suspicious Access", "severity": "High", "user": user}
    return {"event": "Other", "severity": "Info", "user": user}


def analyze_text(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    events = []
    failed_users = Counter()

    for line in lines:
        item = classify_line(line)
        item["log_entry"] = line
        if item["event"] == "Failed Login":
            failed_users[item["user"]] += 1
        events.append(item)

    # Flag all failed logins for an account when it has 3 or more failures.
    for item in events:
        if item["event"] == "Failed Login" and failed_users[item["user"]] >= 3:
            item["event"] = "Multiple Failed Logins"
            item["severity"] = "High"

    counts = Counter(item["event"] for item in events)
    return {
        "events": events,
        "total": len(events),
        "failed": sum(1 for item in events if item["event"] in {"Failed Login", "Multiple Failed Logins"}),
        "successful": counts["Successful Login"],
        "high": sum(1 for item in events if item["severity"] == "High"),
        "counts": dict(counts),
        "failed_users": dict(failed_users),
    }


@app.route("/", methods=["GET", "POST"])
def dashboard():
    report = None
    filename = None
    if request.method == "POST":
        uploaded = request.files.get("logfile")
        if not uploaded or not uploaded.filename:
            flash("Choose a .log, .txt, or .csv file first.", "error")
            return redirect(url_for("dashboard"))

        filename = uploaded.filename
        lower_name = filename.lower()
        if not any(lower_name.endswith(ext) for ext in ALLOWED_EXTENSIONS):
            flash("Unsupported file type. Upload a .log, .txt, or .csv file.", "error")
            return redirect(url_for("dashboard"))

        data = uploaded.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            flash("File is too large. Maximum upload size is 2 MB.", "error")
            return redirect(url_for("dashboard"))

        text = data.decode("utf-8", errors="replace")
        report = analyze_text(text)
        if report["total"] == 0:
            flash("The file was empty or contained no readable log lines.", "error")

    return render_template("dashboard.html", report=report, filename=filename)


@app.route("/demo")
def demo():
    sample = """2026-10-11 09:01:12 FAILED LOGIN user
2026-10-11 09:01:30 FAILED LOGIN user
2026-10-11 09:01:44 FAILED LOGIN user
2026-10-11 09:03:02 SUCCESSFUL LOGIN admin
2026-10-11 09:04:15 UNKNOWN USER hacker
2026-10-11 09:05:20 SUSPICIOUS ACCESS admin
2026-10-11 09:06:01 SUCCESSFUL LOGIN user
2026-10-11 09:07:18 FAILED LOGIN guest
2026-10-11 09:08:43 FILE READ user01
"""
    report = analyze_text(sample)
    return render_template("dashboard.html", report=report, filename="demo_security.log")


@app.route("/download/csv", methods=["POST"])
def download_csv():
    rows_json = request.form.get("rows", "")
    # The report is regenerated from the submitted lines; no server-side state is needed.
    lines = rows_json.splitlines()
    report = analyze_text("\n".join(lines))
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Log Entry", "User", "Event", "Severity"])
    for item in report["events"]:
        writer.writerow([item["log_entry"], item["user"], item["event"], item["severity"]])
    memory = BytesIO(output.getvalue().encode("utf-8-sig"))
    memory.seek(0)
    return send_file(memory, mimetype="text/csv", as_attachment=True, download_name="security_analysis_report.csv")


@app.errorhandler(413)
def too_large(_error):
    flash("File is too large. Maximum upload size is 2 MB.", "error")
    return redirect(url_for("dashboard"))


app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

if __name__ == "__main__":
    app.run(debug=True)