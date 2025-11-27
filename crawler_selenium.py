import json
import time
from urllib.parse import urljoin, urlparse
from collections import deque
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

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
        self.driver = webdriver.Chrome(options=chrome_options)

    def is_valid_link(self, url):
        if not url:
            return False
        parsed = urlparse(url)
        return parsed.netloc == "" or parsed.netloc == self.domain

    def extract_links(self):
        links = []
        for tag in self.driver.find_elements("tag name", "a"):
            href = tag.get_attribute("href")
            if href and self.is_valid_link(href):
                links.append(href)
        return links

    def extract_forms(self, url):
        forms = self.driver.find_elements("tag name", "form")
        form_data = []

        for form in forms:
            inputs = []
            input_elems = form.find_elements("xpath", ".//input|.//textarea|.//select")

            for inp in input_elems:
                name = inp.get_attribute("name")
                t = inp.get_attribute("type") or "text"
                if name:
                    inputs.append({"name": name, "type": t})

            form_data.append({
                "method": (form.get_attribute("method") or "GET").upper(),
                "action": urljoin(url, form.get_attribute("action")),
                "inputs": inputs
            })

        return form_data

    def crawl(self):
        while self.to_crawl and len(self.visited) < self.max_pages:
            url = self.to_crawl.popleft()
            if url in self.visited:
                continue

            try:
                self.driver.get(url)
                time.sleep(1)
            except Exception:
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

        return self.results
