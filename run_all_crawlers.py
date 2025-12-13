# run_all_crawlers.py - WITH LOGIN
from crawler_bs4 import SimpleCrawlerBS4
from crawler_selenium import SimpleCrawlerSelenium
import json

targets = {
    "DVWA": {
        "url": "http://localhost",
        "username": "admin",
        "password": "password",
        "login_url": "http://localhost/login.php"
    },
    "bWAPP": {
        "url": "http://localhost:8080",
        "username": "bee",
        "password": "bug",
        "login_url": "http://localhost:8080/login.php"
    },
    "JuiceShop": {
        "url": "http://localhost:3000",
        "username": None,
        "password": None,
        "login_url": None
    }
}

all_results = {}

# BS4 for DVWA + bWAPP (with login)
for name in ["DVWA", "bWAPP"]:
    config = targets[name]
    crawler = SimpleCrawlerBS4(
        config["url"],
        username=config["username"],
        password=config["password"],
        login_url=config["login_url"]
    )
    all_results[name] = crawler.crawl()

# Selenium for Juice Shop (no login needed)
sel = SimpleCrawlerSelenium(targets["JuiceShop"]["url"])
all_results["JuiceShop"] = sel.crawl()

with open("data/discovered_inputs.json", "w") as f:
    json.dump(all_results, f, indent=4)

print("Saved to data/discovered_inputs.json")