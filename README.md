<div style="width:100%;justify-content:center;"><img src="static/logo.png"></div>

# Description

Information exploit of Target domain. It's a api gethering information and records of webserver. It provide some exploits suggesstions with open port information and scrapping some useful information from the hosted sites. deployed at https://isploit.herokuapp.com/{target-domain}/{shodanapikey}

RUN
---
    root# python3 app.py
    * Serving Flask app "app" (lazy loading)
    * Environment: production
    WARNING: This is a development server. Do not use it in a production deployment.
    Use a production WSGI server instead.
    * Debug mode: on
    * Running on http://127.0.0.1:5001/ (Press CTRL+C to quit)
    * Restarting with stat
    * Debugger is active!
    * Debugger PIN: 709-229-024

USE
---

LOCAL URL - http://127.0.0.1:5001/{target-url}/{(Shodan api-key) or (none)}

GLOBAL URL - https://isploit.herokuapp.com/{target-url}/{shodan api-key}

For Shodan API-KEY login this link <a href="https://www.shodan.io">shodan.io</a>

GET method - URL in browser
POST method - Return json data
    requests.post('URL')