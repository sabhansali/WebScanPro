from crawler_bs4 import SimpleCrawlerBS4
from crawler_selenium import SimpleCrawlerSelenium
import json

targets = {
    "DVWA": "http://localhost",
    "bWAPP": "http://localhost:8080",
    "JuiceShop": "http://localhost:3000"
}

all_results = {}

# BS4 for DVWA + bWAPP
for name in ["DVWA", "bWAPP"]:
    crawler = SimpleCrawlerBS4(targets[name])
    all_results[name] = crawler.crawl()

# Selenium for Juice Shop
sel = SimpleCrawlerSelenium(targets["JuiceShop"])
all_results["JuiceShop"] = sel.crawl()

with open("data/discovered_inputs.json", "w") as f:
    json.dump(all_results, f, indent=4)

print("Saved to data/discovered_inputs.json")
