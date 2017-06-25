#!/usr/bin/env python

import flask
import requests
import shodan
import json
import socket

VIRUSTOTAL_API_KEY = '97f4945cb7c4838c3d8348615e81cc292de1b5cd2a7be4a3772d0475815ee9f6'
SHODAN_API_KEY = 'GEarLJ2xyLPs18TGCoCXrhq6PnPvY28X'

app = flask.Flask(__name__)
api = shodan.Shodan(SHODAN_API_KEY)

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def virustotal_scan(url):
    params = {
        'apikey': VIRUSTOTAL_API_KEY,
        'resource': url,
        'scan': '1'
    }
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params = params)
    return response.json()

def shodan_scan(ip):
    try:
        return api.host(ip)
    except shodan.APIError, e:
        return None


@app.route('/')
def index_page():
    ip = flask.request.args.get("ip", "")
    if ip != "":
        if not is_valid_ip(ip):
            return flask.render_template("home.html", err_msg = "Insert a valid IP address!!!")
        vtotal = virustotal_scan(ip)
        shodan = shodan_scan(ip)
        return flask.render_template("results.html", ip = ip, vtotal = vtotal, shodan = shodan,sh=json.dumps(shodan, indent=2),vtotal_s=json.dumps(vtotal, indent=2))
    else:
        return flask.render_template("home.html")



