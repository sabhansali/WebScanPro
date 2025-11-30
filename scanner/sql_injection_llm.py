# scanner/sql_injection_llm.py
import json
import requests
from ai.llm_engine import LLMEngine

class SQLInjectionTesterLLM:

    def __init__(self):
        self.llm = LLMEngine()
        self.logs_file = "data/vulnerability_logs.json"

    def load_inputs(self):
        with open("data/discovered_inputs.json", "r") as f:
            return json.load(f)

    def test_sql_injection(self, url, field_name):
        payloads = self.llm.generate_sql_payloads(url, field_name)

        if not payloads:
            print(f"[!] No payloads returned for {url} {field_name}")
            return []

        found_vulns = []

        for payload in payloads:
            print(f"Testing payload: {payload}")
            try:
                response = requests.get(url, params={field_name: payload}, allow_redirects=False, timeout=7)
            except Exception as e:
                print(f"[!] Request failed: {e}")
                continue

            body = response.text.lower()
            if any(err in body for err in ["sql", "syntax", "database", "mysql", "warning", "error in your sql"]):
                print(f"[+] SQLi FOUND on {url} field={field_name}")
                found_vulns.append({
                    "url": url,
                    "field": field_name,
                    "payload": payload,
                    "evidence": response.text[:800]
                })

        return found_vulns

    def run(self):
        inputs = self.load_inputs()
        all_vulns = []

        for site_name, items in inputs.items():
            for item in items:
                url = item.get("url")
                for form in item.get("forms", []):
                    for input_field in form.get("inputs", []):
                        field_name = input_field.get("name")
                        if not field_name:
                            continue
                        vulns = self.test_sql_injection(url, field_name)
                        all_vulns.extend(vulns)

        with open(self.logs_file, "w", encoding="utf-8") as f:
            json.dump(all_vulns, f, indent=4, ensure_ascii=False)

        print("\n[✓] SQL Injection Testing Complete.")
        print(f"[+] Logged vulnerabilities to {self.logs_file}")
