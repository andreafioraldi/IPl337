#!/usr/bin/env python

import flask
import requests
import shodan
import json
import socket
import urllib

def generate_data(vtotal_ip, shodan):
    data = {}
    if "asn" in vtotal_ip:
        data["asn"] = vtotal_ip["asn"]
    elif shodan != None and shodan["asn"] != None:
        data["asn"] = shodan["asn"]
    if "country" in vtotal_ip:
        data["country"] = vtotal_ip["country"]
    elif shodan != None and shodan["country_code"] != None:
        data["country"] = shodan["country_code"]
    if shodan != None and shodan["org"] != None:
        data["owner"] = shodan["org"]
    elif "as_owner" in vtotal_ip:
        data["owner"] = vtotal_ip["as_owner"]
    if shodan != None and shodan["isp"] != None:
        data["isp"] = shodan["isp"]
    if shodan != None and shodan["city"] != None:
        data["city"] = shodan["city"]
    if shodan != None and shodan["city"] != None:
        data["city"] = shodan["city"]
    
    if shodan != None and shodan["hostnames"] != None:
        if len(shodan["hostnames"]) > 0:
            data["hostnames"] = ""
            for h in shodan["hostnames"]:
                data["hostnames"] += h + " "
            data["hostnames"] = data["hostnames"][:-2]
    
    return data

def generate_ports(shodan):
    if shodan != None and shodan["ports"] != None and shodan["data"] != None:
        if len(shodan["ports"]) > 0:
            ports = {}
            for p in shodan["ports"]:
                ports[p] = ("none", "none")
            for d in shodan["data"]:
                ports[d["port"]] = (d["transport"], d["_shodan"]["module"])
            return ports
    return None

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

def virustotal_ip_scan(ip):
    params = {
        'ip': ip,
        'apikey': VIRUSTOTAL_API_KEY
    }
    response = urllib.urlopen('https://www.virustotal.com/vtapi/v2/ip-address/report?' + urllib.urlencode(params)).read()
    return json.loads(response)

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
        vtotal_ip = virustotal_ip_scan(ip)
        shodan = shodan_scan(ip)
        data = generate_data(vtotal_ip, shodan)
        ports = generate_ports(shodan)
        return flask.render_template("results.html", data = data, ports = ports, ip = ip, vtotal = vtotal, vtotal_ip = vtotal_ip, ip_vt=json.dumps(vtotal_ip, indent=2))
    else:
        return flask.render_template("home.html")



