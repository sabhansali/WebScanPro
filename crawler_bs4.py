import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
from collections import deque

class SimpleCrawlerBS4:
    def __init__(self, base_url, max_pages=40):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.to_crawl = deque([base_url])
        self.max_pages = max_pages
        self.session = requests.Session()
        self.results = []

    def is_valid_link(self, url):
        if not url:
            return False
        parsed = urlparse(url)
        return parsed.netloc == "" or parsed.netloc == self.domain

    def extract_forms(self, soup, url):
        forms_info = []

        for form in soup.find_all("form"):
            method = form.get("method", "GET").upper()
            action = urljoin(url, form.get("action", url))

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                inp_type = inp.get("type", "text")
                if name:
                    inputs.append({"name": name, "type": inp_type})

            forms_info.append({
                "method": method,
                "action": action,
                "inputs": inputs
            })

        return forms_info

    def extract_links(self, soup, url):
        links = []
        for tag in soup.find_all("a"):
            href = tag.get("href")
            if href and self.is_valid_link(href):
                links.append(urljoin(url, href))
        return links

    def crawl(self):
        while self.to_crawl and len(self.visited) < self.max_pages:
            url = self.to_crawl.popleft()
            if url in self.visited:
                continue

            try:
                response = self.session.get(url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")
            except Exception:
                continue

            self.visited.add(url)

            page_data = {
                "url": url,
                "forms": self.extract_forms(soup, url),
                "links": []
            }

            new_links = self.extract_links(soup, url)
            page_data["links"] = new_links

            for link in new_links:
                if link not in self.visited:
                    self.to_crawl.append(link)

            self.results.append(page_data)

        return self.results
