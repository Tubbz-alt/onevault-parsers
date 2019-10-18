#!/usr/bin/env python3
# coding: utf-8

"""
A basic script to parse OWASP ZAP XML report generated files into seperate host CSV files,
which are formatted ready to be uploaded into oneVault projects.

 - basic use: python3 owasp-zap_to_oneVault.py myScanFile.xml

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
        print ('\nUsage: ' + argv[0] +' <owasp-zap_file.xml>\n')
        print ('*generated files placed under the "output" folder\n')
        sys.exit(2)

tree = ET.parse(parse_file)

new_host = ""
zap_file = None

os.makedirs(os.path.dirname('output/'), exist_ok=True)

for host in tree.findall('site'):
    hostname    = host.get('host')
    port        = host.get('port')

    for findings in host.findall('alerts/alertitem'):
        # Continue parsing the alerts
        name              = findings.find('alert').text
        risk              = findings.find('riskcode').text
        summary           = findings.find('name').text
        details_info      = findings.find('desc').text
        try:
            details_tech    = findings.find('otherinfo').text
        except:
            details_tech    = ''
        try:
            details_ref     = findings.find('reference').text
        except:
            details_ref     = ''
        # Additionally you can extract each affected location on the host from <instances>
        # You will need to do a little work here to add it to the details (:
        # try:
        #     details_affected  = findings.find('instances/instance/uri').text
        #     print (details_affected)
        # except:
        #     details_affected    = ''
        remediation       = findings.find('solution').text
        remediation_ref   = findings.find('reference').text

        if risk == '0':
            risk = 'Informational'
        elif risk == '1':
            risk = 'Low'
        elif risk == '2':
            risk = 'Medium'
        elif risk == '3':
            risk = 'High'
        elif risk == '4':
            risk = 'Critical'
        else:
            risk = 'Critical'
        # Strip out HTML tags, can be left in...but why not?!
        summary = BeautifulSoup(summary, 'html.parser')
        details = BeautifulSoup(details_info + '\n\n\n' + details_tech + '\n\nAdditional references:\n' + details_ref, 'html.parser')
        remediation = BeautifulSoup(remediation, 'html.parser')

        if (risk != 'None'):
            if (hostname != new_host):
                if zap_file is not None:
                    zap_file.close()

                zap_file = open('output/' + hostname + '_owasp-zap_oneVault.csv', 'w')
                csvwriter = csv.writer(zap_file)
                csvwriter.writerow(['hostname', 'name', 'risk', 'summary', 'details', 'remediation'])

                new_host = hostname

        if (hostname == new_host):
            csvwriter.writerow([hostname, name, risk, summary.get_text(), details.get_text(), remediation.get_text()])

            new_host = hostname

print ('\nCheckout the output folder for exported CSV files.\n')