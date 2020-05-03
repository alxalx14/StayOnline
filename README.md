# StayOnline 1.0

## Introduction

> StayOnline is a small Project meant to help website owners defend themselves against DDoS attacks on their websites. It makes use of the Cloudflare RESTful API in order to get the services running again, it has a 7 second max "mitigation" time. StayOnline does not actually mitigate attacks by blocking them, it changes your current Origin IP to one of the set fallback IPs. And it will also activate "High Security Mode" or "Captcha Mode" on your websites to successfully block the attacks. That ofcourse is optional.

## Installation

> Setting up StayOnline is as easy as running the setup.py, wich will proceed to ask you a few questions about your account and will then log all details into a .json config file. After that you will need to run the run.py and specifiy the delay betweeen each check on the website.WARNING: This may interfere with the Cloudflare Ratelimiting(if enabled) and may produce extra costs depending on your settings.
