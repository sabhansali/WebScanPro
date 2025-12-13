import json
import requests
import os
from bs4 import BeautifulSoup


class AuthSessionTester:

    def __init__(self):
        self.session = requests.Session()
        self.results_file = "data/auth_session_results.json"
        self.findings = []

    def log(self, finding):
        self.findings.append(finding)

    def test_default_credentials_dvwa(self):
        url = "http://localhost/login.php"

        creds = [
            ("admin", "password"),
            ("admin", "admin"),
            ("test", "test")
        ]

        for user, pwd in creds:
            s = requests.Session()
            r = s.get(url)
            soup = BeautifulSoup(r.text, "html.parser")
            token = soup.find("input", {"name": "user_token"})

            data = {
                "username": user,
                "password": pwd,
                "Login": "Login"
            }

            if token:
                data["user_token"] = token.get("value")

            resp = s.post(url, data=data)

            if "logout.php" in resp.text.lower():
                self.log({
                    "site": "DVWA",
                    "issue": "Weak / Default Credentials",
                    "username": user,
                    "password": pwd,
                    "severity": "High"
                })
                break

    def test_default_credentials_bwapp(self):
        url = "http://localhost:8080/login.php"

        creds = [
            ("bee", "bug"),
            ("admin", "admin")
        ]

        for user, pwd in creds:
            r = self.session.post(
                url,
                data={
                    "login": user,
                    "password": pwd,
                    "security_level": "0",
                    "form": "submit"
                }
            )

            if "logout.php" in r.text.lower():
                self.log({
                    "site": "bWAPP",
                    "issue": "Weak / Default Credentials",
                    "username": user,
                    "password": pwd,
                    "severity": "High"
                })
                break

    def test_session_fixation_dvwa(self):
        url = "http://localhost/login.php"

        s = requests.Session()
        s.get(url)
        cookie_before = s.cookies.get_dict()

        s.post(url, data={
            "username": "admin",
            "password": "password",
            "Login": "Login"
        })

        cookie_after = s.cookies.get_dict()

        if cookie_before.get("PHPSESSID") == cookie_after.get("PHPSESSID"):
            self.log({
                "site": "DVWA",
                "issue": "Session Fixation",
                "detail": "Session ID did not change after login",
                "severity": "Medium"
            })

    def test_cookie_flags(self):
        test_urls = {
            "DVWA": "http://localhost/",
            "bWAPP": "http://localhost:8080/"
        }

        for site, url in test_urls.items():
            r = self.session.get(url)
            cookies = r.cookies

            for c in cookies:
                if not c.has_nonstandard_attr("HttpOnly"):
                    self.log({
                        "site": site,
                        "issue": "Insecure Cookie",
                        "cookie": c.name,
                        "missing": "HttpOnly",
                        "severity": "Medium"
                    })

                if not c.secure:
                    self.log({
                        "site": site,
                        "issue": "Insecure Cookie",
                        "cookie": c.name,
                        "missing": "Secure",
                        "severity": "Medium"
                    })

    def recommendations(self):
        self.log({
            "recommendations": [
                "Enforce HTTPS across the application",
                "Set Secure and HttpOnly flags on cookies",
                "Regenerate session ID after login",
                "Implement account lockout / rate limiting",
                "Avoid default credentials in production"
            ]
        })

    def run(self):
        print("\n=== Authentication & Session Testing ===\n")

        self.test_default_credentials_dvwa()
        self.test_default_credentials_bwapp()
        self.test_session_fixation_dvwa()
        self.test_cookie_flags()
        self.recommendations()

        with open(self.results_file, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=4)

        print("✓ Auth & Session testing complete")
        print(f"✓ Saved to {self.results_file}")
