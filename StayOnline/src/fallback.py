from requests import get, patch, put, delete, post
import json
from time import sleep
import threading


class cloudflare():
    def __init__(self):
        with open("configs/api.json", "r", encoding="utf-8") as config:
            account = json.loads(config.read(), encoding="utf-8")["cloudflare"]
        self.apiKey = account["api-key"]
        self.apiEmail = account["api-email"]
        self.apiHandler = account["api-handler"]
        with open("configs/api.json", "r", encoding="utf-8") as config:
            self.domains = json.loads(config.read(), encoding="utf-8")["domain"]


    def builder(self, task, ip = None, name = None, proxyStatus = None):
        if(task.lower() == "headers"):
            headers = {
                "X-Auth-Email": self.apiEmail,
                "X-Auth-Key": self.apiKey,
                "Content-Type": "application/json"
            }
            return headers
        elif(task.lower() == "data"):
            data = {
                "type": "A",
                "name": name,
                "content": ip,
                "ttl": 120,
                "proxied": True
            }
            return json.dumps(data)

    def activateUAM(self):
        cfH = self.builder("headers")
        link = "%s/zones/%s/settings/security_level" % (
            self.apiHandler,
            self.domains["id"])
        data = json.dumps({"value": "under_attack"})
        patch(link, data, headers=cfH)
        self.alterSecurity(True)
        sleep(7200)
        data = json.dumps({"value": "medium"})
        print(patch(link, data, headers=cfH).json())
      #  print("UAMM disabled.")
        self.alterSecurity(False)


    def deleteFilter(self, filter_id):
        link = "%s/zones/%s/filters" % (
            self.apiHandler,
            self.domains["id"])
        cfH = self.builder("headers")
        deleteFilterResp = delete(link + "/%s" % filter_id, headers=cfH).json()
        return deleteFilterResp

    def createFilter(self, domain):
        cfH = self.builder("headers")
        link = "%s/zones/%s/filters" % (
            self.apiHandler,
            self.domains["id"])
        data = json.dumps([{"expression": "(http.request.full_uri contains \"%s\")" % domain}])
        createFilterResp = post(link, data, headers=cfH).json()
        return createFilterResp


    def createCaptcha(self, filter_id):
        cfH = self.builder("headers")
        link = "%s/zones/%s/firewall/rules" % (
            self.apiHandler,
            self.domains["id"])
        data = json.dumps(
            [
                {
                    "action": "challenge",
                    "description": "StayOnline CaptchaMode",
                    "filter": {
                        "id": filter_id
                    },
                    "paused": False

            }])
        createFirewallResp = post(link, data, headers=cfH).json()
        self.alterSecurity(True)
        return createFirewallResp

    def alterSecurity(self, mode):
        with open("configs/api.json", "r", encoding="utf-8") as apiFile:
            currentJdata = json.loads(apiFile.read())
            currentJdata["domain"]["currentlySecured"] = bool(mode)
        
        with open("configs/api.json", "w", encoding="utf-8") as apiFile:
            json.dump(currentJdata, apiFile, ensure_ascii=False, indent=4)


    def deleteCaptcha(self, firewall_id, filter_id):
        sleep(7200)
        #self.deleteFilter(firewall_id)
        cfH = self.builder("headers")
        link = "%s/zones/%s/firewall/rules/%s" % (
            self.apiHandler,
            self.domains["id"],
            firewall_id["result"][0]["id"])
        delete(link, headers=cfH)
        self.deleteFilter(firewall_id["result"][0]["filter"]["id"])
        self.alterSecurity(False)
        #print("Disabled Captcha after 2 hours.")
        


    def activateCaptcha(self, domain):
        filterJdata = self.createFilter(domain)
        if(filterJdata["success"] is False):
           # print("Deleting existing Filter.")
            self.deleteFilter(filterJdata["errors"][0]["meta"]["id"])
            filterResp = self.createFilter(domain)
            captchaResp = self.createCaptcha(filterResp["result"][0]["id"])
        else:
            filterResp = self.createFilter(domain)
            if(filterResp["result"] is None):
                self.deleteFilter(filterResp["errors"][0]["meta"]["id"])
                filterResp = self.createFilter(domain)
            captchaResp = self.createCaptcha(filterResp["result"][0]["id"])
       # print("Enabled Captcha succesfully!")
        threading.Thread(target=self.deleteCaptcha, args=(captchaResp, filterResp["result"][0]["id"])).start()
        


    def swapIP(self, domain, ip):
        cfH = self.builder("headers")
        data = self.builder(
            "data", 
            ip, 
            domain,
            self.domains["proxy"])
        link = "%s/zones/%s/dns_records/%s" % (
            self.apiHandler,
            self.domains["id"],
            self.domains["dns"][domain.split(".")[0]]["id"])

        put(link, data, headers=cfH)
        #print("Changed IP to Fallback IP: %s" % ip)