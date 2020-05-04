import threading
import json
#from src.fallback import cloudflare
from src.checkStatus import checker

domains = []
domain = json.loads(open("configs/api.json", "r").read(), encoding="utf-8")["domain"]
security = domain["security"]
for subdomains in domain["dns"]:
    domains.append("%s.%s" %(subdomains, domain["domain"]))

if(len(domains) <= 0):
    print("No domains found, please run setup.py!")
    exit(0)

print("Found, %d domains." % len(domains))
delay = input("Every how many seconds do you wish to check the domain?\n> ")
checker(domains, delay).start(security)