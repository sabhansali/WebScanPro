# scanner/xss_tester.py 
import json
import time
import traceback
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

from ai.llm_engine import LLMEngine

STATIC_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert(1)>",
    "xss123test" 
]


class XSSTester:
    def __init__(self, discovered_inputs_path="data/discovered_inputs.json"):

        self.discovered_inputs_path = discovered_inputs_path

        try:
            self.llm_engine = LLMEngine()
        except Exception as e:
            print(f"[WARNING] LLM initialization failed: {e}")
            self.llm_engine = None

        chrome_opts = Options()
        chrome_opts.add_argument("--headless")
        chrome_opts.add_argument("--no-sandbox")
        chrome_opts.add_argument("--disable-dev-shm-usage")
        chrome_opts.add_argument("--disable-gpu")

        try:
            self.browser = webdriver.Chrome(options=chrome_opts)
        except Exception as e:
            print(f"[WARNING] Selenium initialization failed: {e}")
            self.browser = None

        with open(self.discovered_inputs_path, "r", encoding="utf-8") as f:
            self.targets = json.load(f)

        self.results = []
        self.tests_run = 0

    def normalize_action(self, page_url, action):
        if not action or action == "#":
            return page_url
        return urljoin(page_url, action)


    def get_payloads(self):
        """Gets LLM payloads once, falls back to static."""
        if self.llm_engine:
            try:
                llm_payloads = self.llm_engine.get_xss_payloads()

                if isinstance(llm_payloads, list) and len(llm_payloads) > 0:
                    merged = list(set(llm_payloads + STATIC_XSS_PAYLOADS))
                    print(f"[INFO] Using {len(merged)} payloads (LLM + static)")
                    return merged

            except Exception as e:
                print(f"[WARNING] LLM failed: {e}, using static XSS payloads.")
        
        print(f"[INFO] Using {len(STATIC_XSS_PAYLOADS)} static payloads")
        return STATIC_XSS_PAYLOADS


    def reflected_in_response(self, response_text, payload):
        checks = [
            payload in response_text,
            payload.lower() in response_text.lower(),
            payload.replace("<", "&lt;").replace(">", "&gt;") in response_text,
        ]
        return any(checks)


    def check_dom_xss(self, url, payload):
        if not self.browser:
            return False
            
        try:
            self.browser.get(url)
            time.sleep(1)

            dom = self.browser.page_source.lower()
            payload_lower = payload.lower()

            return (
                payload_lower in dom or
                payload.replace("<", "&lt;").replace(">", "&gt;").lower() in dom
            )
        except Exception as e:
            print(f"    [ERROR] DOM check failed: {e}")
            return False


    def test_forms_from_dict(self, page_url, form_dict, payloads):
        action = self.normalize_action(page_url, form_dict.get("action"))
        method = form_dict.get("method", "GET").lower()
        inputs = form_dict.get("inputs", [])

        print(f"  [FORM] Action: {action}, Method: {method.upper()}")

        for field in inputs:
            name = field.get("name")
            if not name or field.get("type") in ["submit", "button"]:
                continue

            for payload in payloads[:3]:
                data = {name: payload}
                try:
                    if method == "post":
                        r = requests.post(action, data=data, timeout=6)
                    else:
                        r = requests.get(action, params=data, timeout=6)

                    if self.reflected_in_response(r.text, payload):
                        finding = (action, name, payload)
                        if finding not in self.results:
                            self.results.append({
                                "url": action,
                                "field": name,
                                "payload": payload,
                                "type": "reflected-xss",
                                "evidence": r.text[:500]
                            })
                            print("      ✓ REFLECTED XSS FOUND")
                        break
                except Exception:
                    pass


    def test_url_parameters(self, url, payloads):
        """Test URL GET parameters for XSS"""
        parsed = urlparse(url)
        
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params.keys():
                print(f"    [TESTING] URL param: {param_name}")
                
                for payload in payloads[:3]:  # Test first 3 payloads
                    self.tests_run += 1
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    # Rebuild URL
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        resp = requests.get(test_url, timeout=6, allow_redirects=False)
                        print(f"      Payload: {payload[:50]}... -> Status: {resp.status_code}")
                        
                        if self.reflected_in_response(resp.text, payload):
                            self.results.append({
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "type": "reflected-xss-url",
                                "evidence": resp.text[:500]
                            })
                            print(f"      ✓ REFLECTED XSS FOUND in URL param!")
                            break
                            
                    except Exception as e:
                        print(f"      [ERROR] {str(e)[:100]}")
        
        for payload in payloads[:2]:  
            self.tests_run += 1
            if "?" in url:
                test_url = f"{url}&xss_test={payload}"
            else:
                test_url = f"{url}?xss_test={payload}"
            
            try:
                resp = requests.get(test_url, timeout=6, allow_redirects=False)
                
                if self.reflected_in_response(resp.text, payload):
                    self.results.append({
                        "url": test_url,
                        "parameter": "xss_test",
                        "payload": payload,
                        "type": "reflected-xss-url",
                        "evidence": resp.text[:500]
                    })
                    print(f"    ✓ REFLECTED XSS FOUND in injected param!")
                    break
                    
            except Exception as e:
                pass  


    def run(self):
        print("\n" + "="*60)
        print("=== Running XSS Tester (Diagnostic Mode) ===")
        print("="*60)

        payloads = self.get_payloads()
        print(f"\n[PAYLOADS] Total: {len(payloads)}")
        print(f"[PAYLOADS] Sample: {payloads[:3]}\n")

        total_pages = sum(len(pages) for pages in self.targets.values())
        print(f"[TARGETS] Total pages to scan: {total_pages}\n")

        for target_name, pages in self.targets.items():
            print(f"\n{'='*60}")
            print(f"=== Scanning {target_name} ({len(pages)} pages) ===")
            print(f"{'='*60}\n")

            for idx, page in enumerate(pages, 1):
                page_url = page["url"]
                print(f"\n[{idx}/{len(pages)}] Page: {page_url}")

                # Test URL parameters
                self.test_url_parameters(page_url, payloads)

                forms_data = page.get("forms", [])
                if forms_data:
                    print(f"  [FORMS] Found {len(forms_data)} form(s)")
                    for form_idx, form_dict in enumerate(forms_data, 1):
                        print(f"  [FORM {form_idx}]")
                        self.test_forms_from_dict(page_url, form_dict, payloads)
                else:
                    print("  [FORMS] No forms found")

               
                links = page.get("links", [])
                if links:
                    print(f"  [LINKS] Found {len(links)} link(s) - testing URLs")
                    for link in links[:5]:  
                        self.test_url_parameters(urljoin(page_url, link), payloads)

        if self.browser:
            self.browser.quit()

     
        with open("data/xss_results.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4)

        print("\n" + "="*60)
        print(f"=== XSS Testing Complete ===")
        print(f"Tests run: {self.tests_run}")
        print(f"Vulnerabilities found: {len(self.results)}")
        print(f"Results saved to: data/xss_results.json")
        print("="*60 + "\n")
        
        return self.results