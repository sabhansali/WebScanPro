# crawler_selenium.py - IMPROVED (handles SPAs better)
import json
import time
from urllib.parse import urljoin, urlparse
from collections import deque
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

class SimpleCrawlerSelenium:
    def __init__(self, base_url, max_pages=40):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.to_crawl = deque([base_url])
        self.max_pages = max_pages
        self.results = []

        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        self.driver = webdriver.Chrome(options=chrome_options)

    def is_valid_link(self, url):
        """Only allow links from same domain"""
        if not url or url.startswith("javascript:") or url.startswith("mailto:"):
            return False
        
        parsed = urlparse(url)
        return parsed.netloc == "" or parsed.netloc == self.domain

    def extract_links(self):
        """Extract all links from current page"""
        links = set()
        try:
            for tag in self.driver.find_elements("tag name", "a"):
                href = tag.get_attribute("href")
                if href and self.is_valid_link(href):
                    links.add(href)
        except Exception as e:
            print(f"  [ERROR] Extracting links: {e}")
        return list(links)

    def extract_forms(self, url):
        """Extract forms from current page"""
        forms = []
        try:
            form_elements = self.driver.find_elements("tag name", "form")

            for form in form_elements:
                try:
                    action = form.get_attribute("action")
                    action_url = urljoin(url, action) if action else url
                    
                    # Skip external forms
                    if not self.is_valid_link(action_url):
                        continue

                    method = (form.get_attribute("method") or "GET").upper()
                    
                    inputs = []
                    input_elems = form.find_elements("xpath", ".//input|.//textarea|.//select")

                    for inp in input_elems:
                        name = inp.get_attribute("name")
                        inp_type = inp.get_attribute("type") or "text"
                        if name:
                            inputs.append({"name": name, "type": inp_type})

                    if inputs:
                        forms.append({
                            "method": method,
                            "action": action_url,
                            "inputs": inputs
                        })
                except Exception as e:
                    print(f"  [ERROR] Processing form: {e}")
                    continue

        except Exception as e:
            print(f"  [ERROR] Extracting forms: {e}")

        return forms

    def crawl(self):
        while self.to_crawl and len(self.visited) < self.max_pages:
            url = self.to_crawl.popleft()
            
            if url in self.visited:
                continue

            print(f"[CRAWL] {url}")

            try:
                self.driver.get(url)
                time.sleep(2)  # Wait for SPA to load
            except Exception as e:
                print(f"  [ERROR] Failed to load: {e}")
                self.visited.add(url)
                continue

            self.visited.add(url)

            page_data = {
                "url": url,
                "forms": self.extract_forms(url),
                "links": []
            }

            new_links = self.extract_links()
            page_data["links"] = new_links

            for link in new_links:
                if link not in self.visited:
                    self.to_crawl.append(link)

            self.results.append(page_data)
            print(f"  ✓ Forms: {len(page_data['forms'])}, Links: {len(new_links)}")

        self.driver.quit()
        return self.results