import os
from scanner.sql_injection_llm import SQLInjectionTesterLLM
from scanner.xss_tester import XSSTester
from scanner.auth_session_tester import AuthSessionTester
from scanner.access_control_idor_tester import AccessControlIDORTester
import subprocess
import sys

def ensure_directories():
    """Make sure required folders exist."""
    os.makedirs("data", exist_ok=True)

def run_crawlers():
    print("Running all crawlers...")
    subprocess.run([sys.executable, "run_all_crawlers.py"])
    print("Crawler output saved to data/discovered_inputs.json")

def run_sql_injection_tests():
    tester = SQLInjectionTesterLLM()
    tester.run()

def run_xss_tests():
    print("Running XSS Tests...")
    tester = XSSTester()
    tester.run()

def run_auth_session_tests():
    tester = AuthSessionTester()
    tester.run()

def run_access_control_idor_tests():
    tester = AccessControlIDORTester()
    tester.run()

if __name__ == "__main__":
    ensure_directories()
    run_crawlers()
    run_sql_injection_tests()
    run_xss_tests()
    run_auth_session_tests()
    run_access_control_idor_tests()