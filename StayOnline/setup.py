import json
from requests import get
from os import system, name
import sys
import socket



class setup():
    def __init__(self):
        self.clear()
        securityModes = [1, 2, 3, 4]
        self.email = input("Whats your CloudFlare email?\n> ")
        self.api_key = input("Whats your CloudFlare Global API Key?\n> ")
        self.setupDomain = {}
        self.getDomains()

        self.domainToUse = input("For wich domain do you wish to setup the StayOnline services?\n> ")
        try:
            self.dID = self.domain[int(self.domainToUse)]["id"]
        except(KeyError, ValueError):
            print("Invalid Domain, does not exits!\r\nPlease use numbers to select a domain!")
            sys.exit(0)

        self.security = input("""Please choose a security setting. 
           \r [1]Activate UAM(2hrs)                   [2]Just change to a Fallback IP         
           \r [3]Change to Fallback and activate UAM  [4]Activate captcha for that subdomain(2hrs)\n> """)
        try:
            if(int(self.security) not in securityModes):
                print("Invalid input, supported security modes: 1-4.")
                exit(0)
        except ValueError:
            print("Invalid input, supported security modes: 1-4.")
            exit(0)
        numberOfSD = input("How many subdomains do you wish to protect?\n> ")
        self.subdomains(int(numberOfSD))


    def clear(self):
        if name == "nt":
            system("cls")
        else:
            system("clear")
        

    def subdomains(self, domains):
        self.setupDomain[self.dID] = {}
        self.setupDomain[self.dID]["domain"] = self.domain[int(self.domainToUse)]["domain"]
        self.setupDomain[self.dID]["id"] = self.dID
        self.setupDomain[self.dID]["proxy"] = True
        self.setupDomain[self.dID]["security"] = self.security
        self.setupDomain[self.dID]["dns"] = {}
        self.setupDomain[self.dID]["currentlySecured"] = False
        try:
            for _ in range(1, domains + 1):
                verifiedDomain = False
                self.clear()
                while verifiedDomain is False:
                    subDomain = input("Subdomain No.%d\n> " % _)
                    legit = verification().subD("%s.%s" % (subDomain, self.setupDomain[self.dID]["domain"]))
                    if(legit is False):
                        print("Only existing subdomains are supported!\r\n")
                        verifiedDomain = False
                    else:
                        verifiedDomain = True

                self.setupDomain[self.dID]["dns"][subDomain] = {}
                self.setupDomain[self.dID]["dns"][subDomain]["id"] =self.getSDid(subDomain)
                self.setupDomain[self.dID]["dns"][subDomain]["fallbacks"] = []
                fallBack_IPs = input("How many Fallback IPs will you have for %s.%s\n> " % 
                    (subDomain, self.setupDomain[self.dID]["domain"]))
                for y in range(1, int(fallBack_IPs) + 1):
                    ip = input("IP No.%d\n> " % y)
                    self.setupDomain[self.dID]["dns"][subDomain]["fallbacks"].append(ip)
            self.setupFile()
        except(TypeError, ValueError):
                print("PLease provide a number not anything else!")
                sys.exit(0)


    def getDomains(self):
        cfH = {
            "X-Auth-Email": self.email,
            "X-Auth-Key": self.api_key,
            "Content-Type": "application/json"}

        data = get("https://api.cloudflare.com/client/v4/zones/",headers=cfH).json()
        self.domain = {}
        i = 0
        try:
            for x in data["result"]:
                self.domain[i] = {}
                self.domain[i]["id"] = x["id"]
                self.domain[i]["domain"] = x["name"]
                print("[%d]Domain: %s" % (i, x["name"]))
                i+=1
        except TypeError:
            print("Wrong Details! Please check the API Key/Email")
            sys.exit(0)

    def getSDid(self, subdomain):
        headerCF = {
            "X-Auth-Email": self.email,
            "X-Auth-Key": self.api_key,
            "Content-Type": "application/json"
        }
        jResp = get("https://api.cloudflare.com/client/v4/zones/%s/dns_records" % (self.dID), headers=headerCF).json()
        for data in jResp["result"]:
            if(data["name"] == "%s.%s" % (subdomain, self.setupDomain[self.dID]["domain"])):
                return data["id"]

    def setupFile(self):
        print(f"Setup Config for ID: {self.dID}")
        settings = {
            "cloudflare": {
                "api-handler": "https://api.cloudflare.com/client/v4",
                "api-key": self.api_key,
                "api-email": self.email,
            },
            "domain": self.setupDomain[self.dID]
        }


        with open("configs/api.json", "w", encoding="utf-8") as cfg:
            json.dump(settings, cfg, ensure_ascii=False, indent=4)


class verification():
    def __init__(self):
        print("")
    
    def subD(self, domain):
        try: 
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False

setup()