#!/usr/bin/env python

import flask
import requests
import json

app = flask.Flask(__name__)

VIRUSTOTAL_API_KEY = '97f4945cb7c4838c3d8348615e81cc292de1b5cd2a7be4a3772d0475815ee9f6'
virustotal_header = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  My Python requests library example client or username"
}

def virustotal_scan(url):
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource':url, 'scan':'1'}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params = params, headers = virustotal_header)
    json_response = response.json()
    return json.dumps(json_response, indent=2)

@app.route('/')
def index_page():
    input_url = flask.request.args.get("url", "")
    if input_url != "":
        info = virustotal_scan(input_url)
        return flask.render_template("url.html", input_url = input_url, info = info)
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
'''@app.route('/url', methods=['GET', 'POST'])
def url_page():
    if request.method == 'POST':
        return request.form['inputbox']
    else:
        return'''

