#!/usr/bin/env python

import flask
import requests
import json

app = flask.Flask(__name__)

VIRUSTOTAL_API_KEY = '97f4945cb7c4838c3d8348615e81cc292de1b5cd2a7be4a3772d0475815ee9f6'

def virustotal_scan(url):
    params = {
        'apikey': VIRUSTOTAL_API_KEY,
        'resource': url,
        'scan': '1'
    }
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params = params)
    return response.json()

@app.route('/')
def index_page():
    input_url = flask.request.args.get("url", "")
    if input_url != "":
        vtotal = virustotal_scan(input_url)
        return flask.render_template("url.html", input_url = input_url, vtotal = vtotal, vtotal_s=json.dumps(vtotal, indent=2))
    else:
        return """
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Test</title>
</head>
<body>
	<h1>h3770 h4x0r</h1>
	<form action="/">
		<input type="text" size=50 maxsize=200 name="url"/>
		<input type="SUBMIT" value="View">
	</form>
</body>
</html>
"""

