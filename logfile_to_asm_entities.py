#!/usr/bin/python

# logfile_to_asm_entities.py.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
# Version 1.1 - Minor fixes (re: regex for finding status code in w3ce format) and output tweaks (newUrl -> Parsed URL)
# Version 1.2 - Added Support for Parsing Parameters in URL for CLF format and adding them to policy; made File Type and Parameter adding optional via a command line argument
#
# Script that parses web log files and determines URLs that can be added to an F5 BIG-IP ASM Security Policy as Allowed URL entities
# Todo: Determine how URL Parameters appear in W3CE log format; parse them out and support adding to policy

import argparse
import sys
import requests
import json
import getpass
import re

# Taken from http://code.activestate.com/recipes/577058/
def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower() 
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to parse web log files and add them to an ASM security policy')
parser.add_argument('--bigip', '-b', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
parser.add_argument('--logfile', '-l', help='log filename in cwd', required=True)
parser.add_argument('--policy', '-p', help='ASM security policy name', required=True)
parser.add_argument('--protocol', default='https', choices=['https', 'http'], help='protocol for url entities (https or http)')
#Input File Type
parser.add_argument('--format', '-f', choices=['clf', 'w3ce', 'urls'], help='Log File Format: Common Log Format, W3C Extended, URL per Line')

#options for adding entities
parser.add_argument('--addfiletypes', '-af', action='store_true')
parser.add_argument('--addparameters', '-ap', action='store_true')

#responses_to_include
statuscodes = parser.add_argument_group(title='Log file status codes to include')
statuscodes.add_argument('--add200', help='add URLs if log shows 200 response status', action='store_true')
statuscodes.add_argument('--add301', help='add URLs if log shows 301 response status', action='store_true')
statuscodes.add_argument('--add302', help='add URLs if log shows 302 response status', action='store_true')
statuscodes.add_argument('--add304', help='add URLs if log shows 302 response status', action='store_true')

#Safety Checks
safety = parser.add_argument_group(title='Options for disabling Safety Checks')
safety.add_argument('--noprompt', '-n', action='store_true', help='do not prompt to confirm removal of each node')

#Mode
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--updatepolicy', help='add URLs to BIG-IP ASM security Policy', action='store_true')
mode.add_argument('--report', action='store_true', help='Summarize URLs found in log file that would be added; do not touch BIG-IP')


args = parser.parse_args()
contentTypeJsonHeader = {'Content-Type': 'application/json'}

#adapted from https://devcentral.f5.com/articles/demystifying-icontrol-rest-6-token-based-authentication 
def get_auth_token():
    payload = {}
    payload['username'] = args.user
    payload['password'] = passwd
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % args.bigip
    token = bip.post(authurl, headers=contentTypeJsonHeader, auth=(args.user, passwd), data=json.dumps(payload)).json()['token']['token']
    return token

def get_asm_policy_id_from_name(name):
    policies = bip.get('%s/asm/policies/' % (url_base)).json()
    for policy in policies['items']:
        if policy['name'] == name:
	    id = policy['id']
            print ('Found policy: %s' % (id))
    return id

def add_url_to_policy(url, policyId, protocol):
    urlEntityPayload = json.dumps({'name':url, 'performStaging':'true', 'protocol':protocol})
    addUrl = bip.post('%s/asm/policies/%s/urls' % (url_base, policyId), headers=postHeaders, data = urlEntityPayload)
    if addUrl.status_code == 201:
        print('Successfully Created URL: %s' % (url))
    else:
        print('Unsuccessful attempt to create URL: %s - Status Code: %s' % (url, addUrl.status_code))

def add_filetype_to_policy(filetype, policyId):
    filetypePayload = json.dumps({'name':filetype, 'performStaging':'true'})
    addFiletype = bip.post('%s/asm/policies/%s/filetypes' % (url_base, policyId), headers=postHeaders, data = filetypePayload)
    if addFiletype.status_code == 201:
        print('Successfully Created File Type: %s' % (filetype))
    else:
        print('Unsuccessful attempt to create File Type: %s - Status Code: %s' % (filetype, addFiletype.status_code))

def add_parameter_to_policy(parameter, policyId):
    parameterPayload = json.dumps({'name':parameter, 'performStaging':'true'})
    addParameter = bip.post('%s/asm/policies/%s/parameters' % (url_base, policyId), headers=postHeaders, data = parameterPayload)
    if addParameter.status_code == 201:
        print('Successfully Created Parameter: %s' % (parameter))
    else:
        print('Unsuccessful attempt to create Parameter: %s - Status Code: %s' % (parameter, addParameter.status_code))

url_base = ('https://%s/mgmt/tm' % (args.bigip))
user = args.user
passwd = getpass.getpass("Password for " + user + ":")
bip = requests.session()
bip.verify = False
requests.packages.urllib3.disable_warnings()
authtoken = get_auth_token()
authheader = {'X-F5-Auth-Token': authtoken}
bip.headers.update(authheader)

policyId = get_asm_policy_id_from_name(args.policy)
print ('Policy Name: %s ; Policy ID: %s' % (args.policy, policyId))

existingUrls = set()
policyUrls = bip.get('%s/asm/policies/%s/urls' % (url_base, policyId)).json()
for url in policyUrls['items']:
    existingUrls.add(url['name'])

existingFiletypes = set()
policyFiletypes = bip.get('%s/asm/policies/%s/filetypes' % (url_base, policyId)).json()
for filetype in policyFiletypes['items']:
    existingFiletypes.add(filetype['name'])

existingParameters = set()
policyParameters = bip.get('%s/asm/policies/%s/parameters' % (url_base, policyId)).json()
for parameter in policyParameters['items']:
    existingParameters.add(parameter['name'])

print ('**Processing Log File**')
newUrls = set()
newUrlParameterStrings = set()
with open(args.logfile, "r") as file:
    if args.format == 'urls':
        for line in file:
            newUrl = line.rstrip('\r\n')
            newUrls.add(newUrl)
            print ('Parsed Url: %s' % (newUrl))
    elif args.format == 'clf' or args.format == 'w3ce':
        for line in file:
            if args.format == 'clf':
                newUrlSplit = line.split("\"")[1].split()[1].split("?")
                newUrl = newUrlSplit[0]
                statusCode = line.split("\"")[2].split()[0]
                print ('Parsed Url: %s - statusCode: %s' % (newUrl, statusCode))
                if len(newUrlSplit) != 1:
                    newUrlParameterString = newUrlSplit[1]
                    print ('Parsed Parameters: %s' % (newUrlParameterString))
            elif args.format == 'w3ce': 
		newUrl = re.split(' (GET|POST|HEAD|PUT|PATCH) ', line)[2].split()[0]
                statusCode = re.split(' (GET|POST|HEAD|PUT|PATCH) ', line)[2].split()[-3]
                print ('Parsed Url: %s - statusCode: %s' % (newUrl, statusCode))
            if statusCode == '200'and args.add200:
                newUrls.add(newUrl)
                if len(newUrlSplit) != 1:
                    newUrlParameterStrings.add(newUrlSplit[1])
            elif statusCode == '301' and args.add301:
                newUrls.add(newUrl)
                if len(newUrlSplit) != 1:
                    newUrlParameterStrings.add(newUrlSplit[1])
            elif statusCode == '302' and args.add302:
                newUrls.add(newUrl)
                if len(newUrlSplit) != 1:
                    newUrlParameterStrings.add(newUrlSplit[1])
            elif statusCode == '304' and args.add304:
                newUrls.add(newUrl)
                if len(newUrlSplit) != 1:
                    newUrlParameterStrings.add(newUrlSplit[1])
                    print ('added params')
            elif statusCode == '404':
                print ('URL: %s not eligible for adding to policy because status code 404 is ignored' % (newUrl))
            else:
                print ('URL: %s not added - status code %s (possibly not enabled due to missing arguments)' % (newUrl, statusCode))
print ('**Finished Processing Log File**')

newFiletypes = set()
for url in set(newUrls):
    filetype = url.split("/")[-1].split(".")[-1]
    if filetype != '':
        newFiletypes.add(filetype)

newParameters = set()
for urlParameterString in set(newUrlParameterStrings):
    urlParameterPairs = urlParameterString.split("&")
    for urlParameterPair in urlParameterPairs:
	newParameters.add(urlParameterPair.split("=")[0])	

# combine two Python Dicts (our auth token and the Content-type json header) in preparation for doing POSTs
postHeaders = authheader
postHeaders.update(contentTypeJsonHeader)

for url in set(newUrls):
    if url in existingUrls:
        print ('URL: %s already defined in policy' % (url))
    else:
        if args.updatepolicy:
            if args.noprompt:
                add_url_to_policy(url, policyId, args.protocol)
            else:
                queryString = ('Add URL: %s to policy?' % (url))
                if query_yes_no(queryString, default="yes"):
                    add_url_to_policy(url, policyId, args.protocol)
                else:
                    print('Skipping URL: %s' % (url))
        else:
            print('Report Only - New URL: %s' % (url))
                    
if args.addfiletypes:
    for filetype in set(newFiletypes):
        if filetype in existingFiletypes:
            print ('Filetype: %s already defined in policy' % (filetype))
        else:
            if args.updatepolicy:
                if args.noprompt:
                    add_filetype_to_policy(filetype, policyId)
                else:
                    queryString = ('Add Filetype: %s to policy?' % (filetype))
                    if query_yes_no(queryString, default="yes"):
                        add_filetype_to_policy(filetype, policyId)
                    else:
                        print('Skipping Filetype: %s' % (filetype))
            else:
                print('Report Only - New File Type: %s' % (filetype))

if args.addparameters:
    for parameter in set(newParameters):
        if parameter in existingParameters:
            print ('Parameter: %s already defined in policy' % (parameter))
        else:
            if args.updatepolicy:
                if args.noprompt:
                    add_parameter_to_policy(parameter, policyId)
                else:
                    queryString = ('Add Parameter: %s to policy?' % (parameter))
                    if query_yes_no(queryString, default="yes"):
                        add_parameter_to_policy(parameter, policyId)
                    else:
                        print('Skipping Parameter: %s' % (parameter))
            else:
                print('Report Only - New Parameter: %s' % (parameter))
