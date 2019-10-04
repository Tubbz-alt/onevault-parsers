#!/usr/bin/env python3
# coding: utf-8

"""
A basic script to parse BurpSuite XML project files into seperate host CSV files,
which are formatted to be uploaded into oneVault projects.

 - basic use: python3 burp_to_oneVault.py myScanFile.nessus

The XML file is parsed and a CSV file for each host in the file
is created under the /output/ folder. These individual files can then be uploaded
into onevault.tech project assets.

Author: Scapecom 
Version: 1.0
project: onevault.tech

"""
import os
import csv
import sys
from sys import argv
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

try:
    parse_file = sys.argv[1]
except IndexError:
        print ('\nUsage: ' + argv[0] +' <burp_file.xml>\n')
        print ('*generated files placed under the "output" folder\n')
        sys.exit(2)

tree = ET.parse(parse_file)

new_host = ""
burp_file = None

os.makedirs(os.path.dirname('output/'), exist_ok=True)

for findings in tree.findall('issue'):
    for item in findings.findall('host'):
        ipaddr        = item.get('ip')
    # Continue parsing the issues
    url               = findings.find('host').text
    name              = findings.find('name').text
    risk              = findings.find('severity').text
    summary           = findings.find('issueDetail').text
    details_info      = findings.find('issueBackground').text
    details_tech      = findings.find('issueDetail').text
    details_affected  = findings.find('location').text
    remediation       = findings.find('remediationBackground').text

    if risk == 'Information':
        risk = 'Informational'
    # Strip out HTML tags, can be left in...but why not?!
    summary = BeautifulSoup(summary, 'html.parser')
    details = BeautifulSoup(details_info + '\n\n' + details_tech + '\n\nAffected location:\n' + details_affected, 'html.parser')
    remediation = BeautifulSoup(remediation, 'html.parser')

    if (risk != 'None'):
        if (ipaddr != new_host):
            if burp_file is not None:
                burp_file.close()

            burp_file = open('output/' + ipaddr + '_burp_oneVault.csv', 'w')
            csvwriter = csv.writer(burp_file)
            csvwriter.writerow(['ip Address', 'name', 'risk', 'summary', 'details', 'remediation'])

            new_host = ipaddr

        if (ipaddr == new_host):
            csvwriter.writerow([ipaddr, name, risk, summary.get_text(), details.get_text(), remediation.get_text()])

            new_host = ipaddr

print ('\nCheckout the output folder for exported CSV files.\n')