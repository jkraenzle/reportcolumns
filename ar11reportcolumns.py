import os
import sys
import requests
import json
import pandas
import argparse
import getpass

def ar11_rest_api (action, path, appliance, access_token, version = '11.10', payload = None, data = None, additional_headers = None): 
	url = "https://" + appliance + path

	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	if additional_headers != None:
		headers.update (additional_headers)

	if (action == "GET"):
		r = requests.get (url, headers=headers, verify=False)
	elif (action == "POST"):
		if payload != None:
			r = requests.post (url, headers=headers, data=json.dumps (payload), verify=False)
		else:
			r = requests.post (url, headers=headers, data=data, verify=False)
	elif (action == "PUT"):
		r = requests.put (url, headers=headers, data=json.dumps (payload), verify=False)
	elif (action == "DELETE"):
		r = requests.delete (url, headers=headers, verify=False)

	if (r.status_code not in [200, 201, 202, 204]):
		print ("Status code was %s" % r.status_code)
		print ("Error: %s" % r.content)
		result = None
	else:
		if (("Content-Type" in r.headers.keys ()) and ("application/json" in r.headers ["Content-Type"])):
			result = json.loads (r.content)
		elif (("Content-Type" in r.headers.keys ()) and ("application/x-gzip" in r.headers ["Content-Type"])):
			result = r.content
		else:
			result = r.text

	return result

# REST API Python wrapper to authenticate to the server (Login)
# URL: https://<appliance>/api/mgmt.aaa/1.0/token ; pre-version 11.6
# URL: https://<appliance>/api/mgmt.aaa/2.0/token ; version 11.6 or later
# Header: Content-Type:application/json
# Body: {"user_credentials":{"username":<username>, "password":<password>},"generate_refresh_token":"true"}
def ar11_authenticate (appliance, username, password, version='11.10'):

	if (version in ["11.4", "11.5"]):
		url = "https://" + appliance + "/api/mgmt.aaa/1.0/token"
	else:
		url = "https://" + appliance + "/api/mgmt.aaa/2.0/token"
	credentials = {"username":username, "password":password}
	payload = {"user_credentials":credentials, "generate_refresh_token":False}
	headers = {"Content-Type":"application/json"}

	r = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)

	if (r.status_code != 201):
		print ("Status code was %s" % r.status_code)
		print ("Error %s" % r.content)
		return None, None
	else:
		result = json.loads(r.content)

	return result["access_token"]

def html_tables_write (version, doc, advanced):

	dataframe = pandas.DataFrame (doc)
	dataframe = dataframe.fillna (' ')
	
	title = 'AppResponse ' + str(version) + ' Report Columns'

	html_start = '<!doctype html>\n<html lang="en-US">\n'
	header = '<head>\n' + \
		'\t<title>' + title + '</title>\n' + \
		'\t<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">\n' + \
		'</head>'
	body_start = '<body>\n' + \
		'\t<h2 style="text-align:center">' + title + '</h2>\n'
	div_start = '\t<div class="container">\n' + \
		'\t\t<h3>\n' + \
		'\t\t\t<span>Filter</span>\t' + \
		'\t\t\t<input type="search" placeholder="Search ..." class="form-control search-input" data-table="columns-list"/>\n' + \
		'\t\t</h3>\n'

	table = dataframe.to_html (classes=["table", "table-striped", "table-sm", "columns-list"], index=False, justify='left')

	div_end = '\t</div>'

	script = '\t<script>' + \
		'\t\t(function(document) {\n' + \
		"\t\t\t'use strict';\n" + \
		'\t\t\tvar TableFilter = (function(myArray) {\n' + \
		'\t\t\t\tvar search_input;\n' + \
		'\t\t\t\tfunction _onInputSearch(e){\n' + \
		'\t\t\t\t\tsearch_input = e.target;\n' + \
		"\t\t\t\t\tvar tables = document.getElementsByClassName(search_input.getAttribute('data-table'));\n" + \
		'\t\t\t\t\tmyArray.forEach.call(tables, function(table) {\n' + \
		'\t\t\t\t\t\tmyArray.forEach.call(table.tBodies, function(tbody) {\n' + \
		'\t\t\t\t\t\t\tmyArray.forEach.call(tbody.rows, function(row) {\n' + \
		'\t\t\t\t\t\t\t\tvar text_content = row.textContent.toLowerCase();\n' + \
		'\t\t\t\t\t\t\t\tvar search_val = search_input.value.toLowerCase();\n' + \
		"\t\t\t\t\t\t\t\trow.style.display = text_content.indexOf(search_val) > -1 ? '' : 'none';\n" + \
		'\t\t\t\t\t\t\t});\n' + \
		'\t\t\t\t\t\t});\n' + \
		'\t\t\t\t\t});\n' + \
		'\t\t\t\t}\n' + \
		'\t\t\t\treturn {\n' + \
		'\t\t\t\t\tinit: function() {\n' + \
		"\t\t\t\t\t\tvar inputs = document.getElementsByClassName('search-input');\n" + \
		'\t\t\t\t\t\tmyArray.forEach.call(inputs, function(input) {\n' + \
		'\t\t\t\t\t\t\tinput.oninput = _onInputSearch;\n' + \
		'\t\t\t\t\t\t});\n' + \
		'\t\t\t\t\t}\n' + \
		'\t\t\t\t};\n' + \
		'\t\t\t})(Array.prototype);\n' + \
		"\t\t\tdocument.addEventListener('readystatechange', function() {\n" + \
		"\t\t\t\tif (document.readyState === 'complete') {\n" + \
		'\t\t\t\t\tTableFilter.init();\n' + \
		'\t\t\t\t}\n' + \
		'\t\t\t});\n' + \
		'\t\t})(document);\n' + \
		'\t</script>\n' + \
		'\t<script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>\n' + \
		'\t<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.3/umd/popper.min.js" integrity="sha384-ZMP7rVo3mIykV+2+9J3UJ46jBk0WLaUAdn689aCwoqbBJiSnjAK/l8WvCWPIPm49" crossorigin="anonymous"></script>\n' + \
		'\t<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.min.js" integrity="sha384-ChfqqxuZUCnJSK3+MXmPNIyE6ZbWh2IMqE241rYiqJxyMiZ6OW/JmZQ5stwEULTy" crossorigin="anonymous"></script>\n'

	body_end = '</body>'
	html_end = '</html>'

	if advanced == False:
		filename = 'ar' + version + '.html'
	else:
		filename = 'ar' + version + '-advanced.html'
	html_file = open (filename, 'w')
	html_file.write (html_start)
	html_file.write (header)
	html_file.write (body_start)
	html_file.write (div_start)
	html_file.write (table)
	html_file.write (div_end)
	html_file.write (script)
	html_file.write (body_end)
	html_file.write (html_end)

	html_file.close ()

	return

def main():
	# set up arguments in appropriate variables
	parser = argparse.ArgumentParser (description="Python utilities to automate information collection or \
		configuration tasks within AppResponse 11 environments")
	parser.add_argument('--hostname', help="Hostname or IP address of the AppResponse 11 appliance")
	parser.add_argument('--username', help="Username for the appliance")
	parser.add_argument('--password', help="Password for username")
	parser.add_argument('--advanced', help="Add all fields to documentation")
	args = parser.parse_args()

	if args.password == None:
		print ("Please provide password for account %s" % args.username)
		password = getpass.getpass ()
	else:
		password = args.password

	if args.advanced == None:
		advanced = False
	else:
		advanced = True

	access_token = ar11_authenticate (args.hostname, args.username, password)

	info = ar11_rest_api ('GET', '/api/common/1.0/info', args.hostname, access_token)
	version = info['sw_version']
	version = version.split(" ", 1)[0]

	sources = ar11_rest_api ('GET', '/api/npm.reports.sources/1.0/sources', args.hostname, access_token, version)

	source_list = []
	doc = {'Label':[], 'ID':[], 'Description':[], 'Unit':[], 'Type':[], 'Source':[], 'Grouped By':[], 'Groups':[]}
	for item in sources ['items']:
		if item['name'] not in source_list:
			source_list.append (item['name'])
		if item['info']['external_api_access'] == 'supported' or (item['info']['external_api_access'] == 'not_supported' and advanced == True):
			for column in item['columns']:
				doc['Label'].append(column['label'])
				doc['ID'].append(column['id'])
				doc['Description'].append(column['description'])
				doc['Unit'].append(column['unit'])
				doc['Type'].append(column['type'])
				doc['Source'].append(column['source_name'])
				if 'grouped_by' in column:
					value = column['grouped_by']
				else:
					value = ""
				doc['Grouped By'].append(value)
				if 'groups' in column:
					value = ','.join(column['groups'])
				else:
					value = ""
				doc['Groups'].append(value)

	source_file = open ('source.json', 'w')
	source_file.write (json.dumps(sources))
	source_file.close ()

	sourcelist_file = open ('sourcelist.txt', 'w')
	sourcestr = '\n'
	sourcelist_file.write (sourcestr.join(source_list))
	sourcelist_file.close ()

	html_tables_write (version, doc, advanced)

if __name__ == "__main__":
	main()
