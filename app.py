
import sqlite3
import json
from datetime import datetime
from html import escape

from flask import Flask, Response, render_template, request

from scanner import scan_network
from analyzer import analyze_host


app = Flask(__name__)

DB_NAME = "netguard.db"

latest_results = []
latest_target = ""


# ---------------- DATABASE ----------------

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            results TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_scan(target, results):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (target, scan_time, results)
        VALUES (?, ?, ?)
    """, (
        target,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        json.dumps(results)
    ))

    conn.commit()
    conn.close()


init_db()


# ---------------- DASHBOARD ----------------

@app.route("/", methods=["GET", "POST"])
def dashboard():
    global latest_results, latest_target

    total_hosts = 0
    total_ports = 0

    risk_counts = {
        "High": 0,
        "Medium": 0,
        "Info": 0
    }

    error = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        if not target:
            error = "Please enter a network target."

        else:
            scan_data = scan_network(target)

            if "error" in scan_data:
                error = scan_data["error"]

            else:
                results = scan_data.get("hosts", [])

                for host in results:
                    analyze_host(host)

                latest_results = results
                latest_target = target

                save_scan(target, results)

                total_hosts = len(results)

                for host in results:
                    total_ports += len(host.get("ports", []))

                    for finding in host.get("findings", []):
                        level = finding.get("level")

                        if level in risk_counts:
                            risk_counts[level] += 1

    return render_template(
        "index.html",
        results=latest_results,
        target=latest_target,
        total_hosts=total_hosts,
        total_ports=total_ports,
        risk_counts=risk_counts,
        error=error
    )


# ---------------- SCAN HISTORY ----------------

@app.route("/history")
def history():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, target, scan_time
        FROM scans
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()
    conn.close()

    return render_template("history.html", scans=scans)


# ---------------- SCAN DETAILS ----------------

@app.route("/history/<int:scan_id>")
def scan_details(scan_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    )

    scan = cursor.fetchone()
    conn.close()

    if scan is None:
        return "Scan record not found", 404

    results = json.loads(scan["results"])

    return render_template(
        "scan_details.html",
        scan=scan,
        results=results
    )


# ---------------- DOWNLOAD REPORT ----------------

@app.route("/download")
def download_report():
    if not latest_results:
        return "No scan results available. Run a scan first.", 400

    report = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>NetGuard Security Report</title>
        <style>
            body {
                font-family: Arial;
                background: #f1f5f9;
                padding: 25px;
            }

            h1, h2 {
                color: #0f172a;
            }

            .host {
                background: white;
                padding: 20px;
                margin: 20px 0;
                border-radius: 8px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th, td {
                padding: 10px;
                border: 1px solid #ccc;
                text-align: left;
            }

            .High { color: red; }
            .Medium { color: #b45309; }
            .Info { color: blue; }
        </style>
    </head>
    <body>
        <h1>NetGuard Security Report</h1>
        <p><b>Target:</b> TARGET_VALUE</p>
        <p><b>Generated:</b> DATE_VALUE</p>
    """

    report = report.replace(
        "TARGET_VALUE",
        escape(latest_target)
    )

    report = report.replace(
        "DATE_VALUE",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    for host in latest_results:
        report += f"""
        <div class="host">
            <h2>Host: {escape(str(host.get('ip', 'Unknown')))}</h2>

            <h3>Open Ports</h3>

            <table>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
        """

        for port in host.get("ports", []):
            report += f"""
                <tr>
                    <td>{escape(str(port.get('port', '')))}</td>
                    <td>{escape(str(port.get('protocol', '')))}</td>
                    <td>{escape(str(port.get('service', '')))}</td>
                    <td>{escape(str(port.get('version', '')))}</td>
                </tr>
            """

        report += """
            </table>
            <h3>Security Findings</h3>
        """

        findings = host.get("findings", [])

        if findings:
            for finding in findings:
                level = escape(str(finding.get("level", "Info")))
                message = escape(str(finding.get("message", "")))

                report += f"""
                <p class="{level}">
                    <b>{level}:</b> {message}
                </p>
                """
        else:
            report += "<p>No security findings recorded.</p>"

        report += "</div>"

    report += """
    </body>
    </html>
    """

    return Response(
        report,
        mimetype="text/html",
        headers={
            "Content-Disposition":
            "attachment; filename=NetGuard_Report.html"
        }
    )


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
