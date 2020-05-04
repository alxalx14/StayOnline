import threading
from time import sleep
from requests import get, exceptions
from src.fallback import cloudflare
from os import system, name
import socket
import json
import random
import sys

class checker():
    def __init__(self, domainList, delayS):
        self.domains = domainList
        self.activeThreads = []
        self.delay = int(delayS)
        self.badCodes = [521, 522, 503]
        self.isSecured = False
        self.domainStauts = "\x1b[93mChecking...."
    def getLiveIP(self, domain):
        domain = domain.split(".")[0]
        IPList = json.loads(open("configs/api.json", "r", encoding="utf-8").read(), encoding="utf-8")["domain"]["dns"][domain]["fallbacks"]
        for ips in IPList:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            r = s.connect_ex((ips, 80))
            if(r == 0):
                return ips
        return

    def clear(self):
        if name == "nt":
            system("cls")
        else:
            system("clear")

    def showInfo(self, domain):
        domain = domain.split(".")
        domain = domain[1] + "." + domain[2]
        while True:
            if(self.checkSecurity() is True):
                sec = "\x1b[92mEnabled"
            else:
                sec = "\x1b[91mDisabled"
            self.clear()
            sys.stdout.write("\r\x1b[95mCurrent Status\x1b[97m: %s \x1b[95mDomain\x1b[97m: \x1b[96m%s\n         \x1b[95mSecurity Status\x1b[97m: %s\r\n\x1b[96mSecurity Provided by StayOnline 1.0" % (
                self.domainStauts,
                domain,
                sec))
            sleep(5)


    def checkSecurity(self):
        isSecured = json.loads(open("configs/api.json", "r", encoding="utf-8").read(), encoding="utf-8")["domain"]["currentlySecured"]
        return isSecured


    def levelOne(self, domain):
        #print("Domain %s went down, attempting mitigation!" % domain)
        threading.Thread(target=cloudflare().activateUAM).start()


    def levelTwo(self, domain):
        #print("Domain %s went down, attempting mitigation!" % domain)
        lIP = self.getLiveIP(domain)
        cloudflare().swapIP(domain, lIP)


    def levelThree(self, domain):
        #print("Domain %s went down, attempting mitigation!" % domain)
        lIP = self.getLiveIP(domain)
        threading.Thread(target=cloudflare().activateUAM).start()
        cloudflare().swapIP(domain, lIP)
        

    def levelFour(self, domain):
        #print("Domain %s went down, attempting mitigation!" % domain)
        cloudflare().activateCaptcha(domain)
       # threading.Thread(cloudflare().activateCaptcha, args=(domain, )).start()


    def secure(self, domain, level):
        return{
            "1": self.levelOne,
            "2": self.levelTwo,
            "3": self.levelThree,
            "4": self.levelFour,
        }.get(level, lambda: None)(domain)


    def domainHandler(self, domain, level):
        sc = 200
        while True:
            try:
                sc = get("https://%s/checkingIfUP" % domain, timeout=3).status_code
            except exceptions.TooManyRedirects:
                pass
            except (exceptions.ReadTimeout, ConnectionError):
                if(self.checkSecurity() is False):
                    self.domainStauts = "\x1b[91mDown"
                    #print("Domain has not responded, attempting mitigation!")
                    self.secure(domain, level)
                    sleep(self.delay)
                    pass

            if(self.checkSecurity() is False):
                if(sc in self.badCodes):
                    self.domainStauts = "\x1b[91mDown"
                    #print("Domain has not responded, attempting mitigation!")
                    self.secure(domain, level)

            if(sc not in self.badCodes):
                    self.domainStauts = "\x1b[92mUp"
            sleep(self.delay)
            

            


    def start(self, securityLevel):
        for domain in self.domains:
            t = threading.Thread(target=self.domainHandler, args=(domain, securityLevel))
            self.activeThreads.append(t)
            t.start()
        threading.Thread(target=self.showInfo, args=(domain, )).start()
            #print("Started StayOnline monitor on %s" % domain)


        for threads in self.activeThreads:
            threads.join()
            self.activeThreads.remove(threads)
