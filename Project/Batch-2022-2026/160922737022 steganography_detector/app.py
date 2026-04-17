import webbrowser
import threading
from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from config import Config

from utils.auth import login_required, authenticate, hash_password
from detector.stego_detector import analyze_file
from utils.blockchain import record_hash
from utils.pdf_report import generate_pdf
from utils.risk import calculate_risk

from models.models import db, User, ScanHistory

import os
from datetime import datetime


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)


# -------------------- INITIAL SETUP --------------------
with app.app_context():
    db.create_all()
    if not User.query.first():
        admin = User(
            username="admin",
            password=hash_password("admin")
        )
        db.session.add(admin)
        db.session.commit()


# -------------------- AUTH --------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if authenticate(
            request.form.get("username"),
            request.form.get("password")
        ):
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")

    return render_template("login.html")


# -------------------- DASHBOARD --------------------
@app.route("/dashboard")
@login_required
def dashboard():
    scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
    return render_template("dashboard.html", scans=scans)


# -------------------- ANALYZE --------------------
@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    result = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if uploaded_file and uploaded_file.filename:
            save_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                uploaded_file.filename
            )
            uploaded_file.save(save_path)

            findings = analyze_file(save_path)
            risk = calculate_risk(findings)
            hash_value = record_hash(findings)

            scan = ScanHistory(
                filename=uploaded_file.filename,
                result=str(findings),
                risk=risk,
                hash_value=hash_value,
                timestamp=datetime.utcnow()
            )

            db.session.add(scan)
            db.session.commit()
            result = scan

    return render_template("analyze.html", result=result)


# -------------------- HISTORY --------------------
@app.route("/history")
@login_required
def history():
    scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
    return render_template("history.html", scans=scans)


# -------------------- REPORT --------------------
@app.route("/report/<int:scan_id>")
@login_required
def report(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    pdf_path = generate_pdf(scan)
    return send_file(pdf_path, as_attachment=True)


# -------------------- BATCH SCAN --------------------
@app.route("/batch", methods=["GET", "POST"])
@login_required
def batch():
    results = None

    if request.method == "POST":
        folder = request.form.get("folder")
        if folder and os.path.isdir(folder):
            from detector.batch_scanner import batch_scan
            results = batch_scan(folder)

    return render_template("batch.html", results=results)


# -------------------- CHAIN OF CUSTODY --------------------
@app.route("/custody/<int:scan_id>")
@login_required
def custody(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    from utils.custody import generate_custody_record
    path = generate_custody_record(scan)
    return send_file(path, as_attachment=True)


# -------------------- MAIN --------------------
if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("database", exist_ok=True)
    os.makedirs("static/heatmaps", exist_ok=True)

    def open_browser():
        webbrowser.open_new("http://127.0.0.1:5000")

    # Open browser after Flask starts
    threading.Timer(1.5, open_browser).start()

    app.run(host="127.0.0.1", port=5000, debug=False)