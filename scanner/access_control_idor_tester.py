import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import os


class AccessControlIDORTester:

    def __init__(self):
        self.session = requests.Session()
        self.findings = []
        self.debug_logs = []

        self.output_file = "data/access_control_findings.json"
        self.debug_file = "data/access_control_debug.log"

        self.dvwa_user = os.getenv("DVWA_USER", "admin")
        self.dvwa_pass = os.getenv("DVWA_PASS", "password")

        self.bwapp_user = os.getenv("BWAPP_USER", "bee")
        self.bwapp_pass = os.getenv("BWAPP_PASS", "bug")

    def debug(self, msg):
        print(msg)
        self.debug_logs.append(msg)

    # Authentication
    def login_dvwa_bwapp(self):
        try:
            # DVWA
            dvwa_login = "http://localhost/login.php"
            r = self.session.get(dvwa_login, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            token = soup.find("input", {"name": "user_token"})

            data = {
                "username": self.dvwa_user,
                "password": self.dvwa_pass,
                "Login": "Login"
            }
            if token:
                data["user_token"] = token.get("value")

            self.session.post(dvwa_login, data=data, timeout=5)
            self.session.cookies.set("security", "low", domain="localhost", path="/")
            self.debug("[LOGIN] DVWA authenticated")

            # bWAPP
            self.session.post(
                "http://localhost:8080/login.php",
                data={
                    "login": self.bwapp_user,
                    "password": self.bwapp_pass,
                    "form": "submit"
                },
                timeout=5
            )
            self.debug("[LOGIN] bWAPP authenticated")

        except Exception as e:
            self.debug(f"[LOGIN ERROR] {e}")

    # IDOR PARAMETER MANIPULATION
    def mutate_id_param(self, url):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        if "id" not in qs:
            return None

        original_id = qs["id"][0]
        mutated_urls = []

        for test_id in ["1", "2", "3", "999"]:
            if test_id != original_id:
                qs["id"] = test_id
                new_query = urlencode(qs, doseq=True)
                mutated_urls.append(
                    urlunparse(parsed._replace(query=new_query))
                )

        return mutated_urls

    # IDOR DETECTION LOGIC
    def detect_idor(self, baseline, injected):
        baseline_lower = baseline.lower()
        injected_lower = injected.lower()

        baseline_count = baseline_lower.count("first name")
        injected_count = injected_lower.count("first name")

        if injected_count > baseline_count:
            return True

        if baseline != injected:
            return True

        return False

    def run(self):
        print("\n=== Access Control & IDOR Tester ===\n")

        self.login_dvwa_bwapp()

        test_targets = [
            "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit",
            "http://localhost/vulnerabilities/fi/?page=include.php",
            "http://localhost:8080/userinfo.php?id=1"
        ]

        for url in test_targets:
            self.debug(f"[TEST] {url}")

            try:
                baseline = self.session.get(url, timeout=6).text
            except Exception:
                continue

            mutated_urls = self.mutate_id_param(url)
            if not mutated_urls:
                continue

            for test_url in mutated_urls:
                try:
                    r = self.session.get(test_url, timeout=6)

                    if self.detect_idor(baseline, r.text):
                        vuln = {
                            "issue": "Insecure Direct Object Reference (IDOR)",
                            "url": test_url,
                            "original_url": url,
                            "impact": "Unauthorized access to another user's data",
                            "severity": "High",
                            "recommendation": [
                                "Enforce server-side authorization checks",
                                "Bind objects to authenticated user identity",
                                "Use indirect object references",
                                "Implement RBAC or ABAC policies"
                            ]
                        }
                        self.findings.append(vuln)
                        self.debug(f"[VULN] {vuln}")
                        break

                except Exception:
                    pass

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=4)

        with open(self.debug_file, "w", encoding="utf-8") as f:
            f.write("\n".join(self.debug_logs))

        print("\n✓ Access Control testing complete")
        print(f"✓ Findings: {len(self.findings)}")
        print(f"✓ Saved to {self.output_file}")

        return self.findings
