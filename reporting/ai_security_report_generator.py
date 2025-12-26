import json
import os
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import MinMaxScaler
import numpy as np
from datetime import datetime


class AISecurityReportGenerator:

    def __init__(self):
        self.input_files = [
            "data/vulnerability_logs.json",
            "data/xss_results.json",
            "data/auth_session_results.json",
            "data/access_control_findings.json"
        ]

        self.output_json = "reports/security_report_data.json"
        self.output_html = "reports/security_report.html"

        os.makedirs("reports", exist_ok=True)

        self.vulnerabilities = []

        self.VULN_TYPE_MAPPING = {
            "reflected-xss-url": "Cross-Site Scripting (XSS)",
            "stored-xss": "Cross-Site Scripting (XSS)",
            "dom-xss": "Cross-Site Scripting (XSS)",

            "Weak / Default Credentials": "Authentication Misconfiguration",
            "Session Fixation": "Session Management Vulnerability",

            "Insecure Direct Object Reference (IDOR)": "Insecure Direct Object Reference (IDOR)"
        }

        self.DEFAULT_MITIGATIONS = {
            "Cross-Site Scripting (XSS)": (
                "Validate and sanitize all user inputs. "
                "Apply proper output encoding. "
                "Implement Content Security Policy (CSP). "
                "Avoid reflecting untrusted input in responses."
            ),
            "Authentication Misconfiguration": (
                "Remove default credentials before deployment. "
                "Enforce strong password policies. "
                "Implement account lockout and rate limiting."
            ),
            "Session Management Vulnerability": (
                "Regenerate session IDs after successful login. "
                "Set Secure and HttpOnly flags on cookies. "
                "Enforce HTTPS across the application."
            ),
            "Insecure Direct Object Reference (IDOR)": (
                "Enforce server-side authorization checks. "
                "Bind objects to authenticated user identity. "
                "Use indirect object references. "
                "Implement RBAC or ABAC policies."
            )
        }

    def load_results(self):
        for file in self.input_files:
            if os.path.exists(file):
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.vulnerabilities.extend(data)

    def normalize_vulnerabilities(self):
        normalized = []

        for v in self.vulnerabilities:
            raw_type = v.get("type") or v.get("issue") or "Unknown"
            vuln_type = self.VULN_TYPE_MAPPING.get(raw_type, raw_type)

            endpoint = (
                v.get("endpoint")
                or v.get("url")
                or v.get("tested_url")
                or v.get("original_url")
            )

            # Inject logical endpoints for non-URL issues
            if not endpoint:
                if vuln_type == "Authentication Misconfiguration":
                    endpoint = "Application Login Module"
                elif vuln_type == "Session Management Vulnerability":
                    endpoint = "Application Session Handling"
                else:
                    endpoint = "Application-Wide"

            impact = v.get("impact", "Security impact detected")

            recommendation = v.get("recommendation")
            if isinstance(recommendation, list):
                recommendation = " ".join(recommendation)

            if not recommendation or recommendation.strip() == "":
                recommendation = self.DEFAULT_MITIGATIONS.get(vuln_type, "Apply security best practices.")

            raw_severity = v.get("severity", "Medium")

            # Skip meaningless unknown rows
            if vuln_type == "Unknown" and endpoint == "Application-Wide":
                continue

            normalized.append({
                "type": vuln_type,
                "endpoint": endpoint,
                "impact": impact,
                "recommendation": recommendation,
                "raw_severity": raw_severity
            })

        self.vulnerabilities = normalized

    def train_severity_classifier(self):
        texts = [
            "sql injection database compromise critical",
            "stored xss reflected xss account takeover",
            "idor unauthorized data access",
            "weak authentication default credentials",
            "session fixation hijacking",
            "low impact informational issue"
        ]
        labels = ["Critical", "High", "High", "High", "Medium", "Low"]

        self.vectorizer = TfidfVectorizer()
        X = self.vectorizer.fit_transform(texts)

        self.classifier = LogisticRegression(max_iter=500)
        self.classifier.fit(X, labels)

    def classify_severity(self):
        for v in self.vulnerabilities:
            text = f"{v['type']} {v['impact']}"
            vec = self.vectorizer.transform([text])
            v["ai_severity"] = self.classifier.predict(vec)[0]

    def calculate_risk_scores(self):
        severity_map = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }

        scores = [severity_map.get(v["ai_severity"], 2) for v in self.vulnerabilities]

        scaler = MinMaxScaler(feature_range=(10, 100))
        scaled = scaler.fit_transform(np.array(scores).reshape(-1, 1))

        for i, v in enumerate(self.vulnerabilities):
            v["risk_score"] = int(scaled[i][0])

    def generate_executive_summary(self):
        count = len(self.vulnerabilities)
        sev_counts = Counter(v["ai_severity"] for v in self.vulnerabilities)

        return (
            f"This security assessment identified {count} vulnerabilities across the application. "
            f"Critical and High risk issues require immediate remediation. "
            f"Most common severity observed: {sev_counts.most_common(1)[0][0]}."
        )

    def export_json(self):
        with open(self.output_json, "w", encoding="utf-8") as f:
            json.dump(self.vulnerabilities, f, indent=4)

    def export_html(self):
        summary = self.generate_executive_summary()
        rows = ""

        for v in self.vulnerabilities:
            rows += f"""
            <tr>
                <td>{v['type']}</td>
                <td>{v['endpoint']}</td>
                <td>{v['ai_severity']}</td>
                <td>{v['risk_score']}</td>
                <td>{v['recommendation']}</td>
            </tr>
            """

        html = f"""
        <html>
        <head>
            <title>WebScanPro Security Report</title>
            <style>
                body {{ font-family: Arial; margin: 40px; }}
                h1 {{ color: #b30000; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ccc; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>

        <h1>WebScanPro – AI Security Assessment Report</h1>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>

        <h2>Executive Summary</h2>
        <p>{summary}</p>

        <h2>Detected Vulnerabilities</h2>
        <table>
            <tr>
                <th>Vulnerability</th>
                <th>Affected Endpoint</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Suggested Mitigation</th>
            </tr>
            {rows}
        </table>

        </body>
        </html>
        """

        with open(self.output_html, "w", encoding="utf-8") as f:
            f.write(html)

    def run(self):
        print("Generating AI Security Report (Week 7)")
        self.load_results()
        self.normalize_vulnerabilities()
        self.train_severity_classifier()
        self.classify_severity()
        self.calculate_risk_scores()
        self.export_json()
        self.export_html()
        print("Report generated successfully")
        print(f"HTML Report: {self.output_html}")
        print(f"Structured Data: {self.output_json}")


if __name__ == "__main__":
    AISecurityReportGenerator().run()
