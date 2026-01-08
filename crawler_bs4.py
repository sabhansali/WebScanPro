#  crawler_bs4.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
import time
from dotenv import load_dotenv
import os

load_dotenv()


class SimpleCrawlerBS4:
    def __init__(self, base_url, login_url=None, username=None, password=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.visited = set()
        self.to_crawl = [self.base_url]
        self.results = []
        self.login_url = login_url
        self.username = username
        self.password = password

    def get_csrf_token(self, html):
        soup = BeautifulSoup(html, "html.parser")
        token = soup.find("input", {"type": "hidden"})
        if token and token.get("value"):
            return token["value"]
        return None

    def login(self):
        if not self.login_url:
            return

        try:
            print(f"[LOGIN] GET {self.login_url}")
            response = self.session.get(self.login_url)
            csrf = self.get_csrf_token(response.text)

            # ---------------- DVWA LOGIN ----------------
            if "localhost" in self.base_url and "8080" not in self.base_url:
                login_data = {
                    "username": self.username,
                    "password": self.password,
                    "Login": "Login",
                }
                if csrf:
                    login_data["user_token"] = csrf

            # ---------------- bWAPP LOGIN ----------------
            elif "8080" in self.base_url:
                login_data = {
                    "login": self.username,
                    "password": self.password,
                    "security_level": "0",
                    "form": "submit"
                }
                if csrf:
                    login_data["token"] = csrf

            else:
                login_data = {
                    "username": self.username,
                    "password": self.password
                }

            print(f"[LOGIN] POST {self.login_url}")
            post_response = self.session.post(self.login_url, data=login_data)

            if post_response.status_code == 200:
                print("[LOGIN] Successful")
            else:
                print(f"[LOGIN][ERROR] Status: {post_response.status_code}")

        except Exception as e:
            print(f"[LOGIN][ERROR] {e}")

    def extract_links(self, soup, current_url):
        links = set()
        for tag in soup.find_all("a", href=True):
            abs_url = urljoin(current_url, tag["href"])
            if abs_url.startswith(self.base_url):
                links.add(abs_url)
        return list(links)

    def extract_forms(self, soup, url):
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all("input"):
                inputs.append({
                    "name": inp.get("name"),
                    "type": inp.get("type"),
                    "value": inp.get("value")
                })
            forms.append({
                "action": form.get("action"),
                "method": form.get("method"),
                "inputs": inputs,
                "url": url
            })
        return forms

    def crawl(self, max_depth=3):
        self.login()

        depth = 0
        while self.to_crawl and depth < max_depth:
            url = self.to_crawl.pop(0)
            if url in self.visited:
                continue

            print(f"[CRAWL] {url}")

            try:
                response = self.session.get(url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")

                page_data = {
                    "url": url,
                    "forms": self.extract_forms(soup, url),
                    "links": self.extract_links(soup, url)
                }
                self.results.append(page_data)

                for link in page_data["links"]:
                    if link not in self.visited:
                        self.to_crawl.append(link)

            except Exception as e:
                print(f"[CRAWL][ERROR] {e}")

            self.visited.add(url)
            depth += 1

        # After normal crawl, hit challenge pages
        self.crawl_sqli_challenges()
        self.crawl_xss_challenges()

        return self.results

    def crawl_sqli_challenges(self):
        dvwa = [
            "http://localhost/vulnerabilities/sqli/",
            "http://localhost/vulnerabilities/sqli_blind/"
        ]
        bwapp = [
            "http://localhost:8080/bWAPP/sqli_1.php",
            "http://localhost:8080/bWAPP/sqli_2.php"
        ]

        targets = dvwa if "8080" not in self.base_url else bwapp

        for url in targets:
            try:
                print(f"[CRAWL][SQLi] {url}")
                r = self.session.get(url)
                soup = BeautifulSoup(r.text, "html.parser")
                self.results.append({
                    "url": url,
                    "forms": self.extract_forms(soup, url),
                    "links": self.extract_links(soup, url)
                })
            except Exception as e:
                print(f"[ERROR][SQLi] {url}: {e}")

    def crawl_xss_challenges(self):
        dvwa = [
            "http://localhost/vulnerabilities/xss_r/",
            "http://localhost/vulnerabilities/xss_s/",
            "http://localhost/vulnerabilities/xss_d/"
        ]
        bwapp = [
            "http://localhost:8080/bWAPP/xss_get.php",
            "http://localhost:8080/bWAPP/xss_post.php",
            "http://localhost:8080/bWAPP/xss_stored.php"
        ]

        targets = dvwa if "8080" not in self.base_url else bwapp

        for url in targets:
            try:
                print(f"[CRAWL][XSS] {url}")
                r = self.session.get(url)
                soup = BeautifulSoup(r.text, "html.parser")
                self.results.append({
                    "url": url,
                    "forms": self.extract_forms(soup, url),
                    "links": self.extract_links(soup, url)
                })
            except Exception as e:
                print(f"[ERROR][XSS] {url}: {e}")


if __name__ == "__main__":
    c = SimpleCrawlerBS4("http://localhost")
    print(json.dumps(c.crawl(), indent=4))
