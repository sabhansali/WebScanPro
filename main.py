from scanner.sql_injection_llm import SQLInjectionTesterLLM
import subprocess
import sys

def run_crawlers():
    print("Running all crawlers...")
    subprocess.run([sys.executable, "run_all_crawlers.py"])
    print("Crawler output saved to data/discovered_inputs.json")

def run_sql_injection_tests():
    tester = SQLInjectionTesterLLM()
    tester.run()

if __name__ == "__main__":
    run_crawlers()
    run_sql_injection_tests()